---
name: faithful-ports-land-not-held
description: "A faithful port LANDS regardless of corpus regression — never hold/scope/revert it to protect the gauge; the regression is the diagnostic for the next fix. Holding = local minima."
metadata:
  node_type: memory
  type: feedback
  originSessionId: c0fe6b35-0fb2-4ed2-90d8-ec93de63680c
---

User directive (2026-07-11, reiterated after catching a drift in the lead's monologue): **if a port is FAITHFUL, land it — we do not care that it regresses the corpus.** A faithful port pays off eventually; the regression it surfaces is the DIAGNOSTIC that names the next non-Ghidra code to fix. Reverting/holding/scoping-around a faithful port to keep the corpus number from dipping is the LOCAL-MINIMA trap — you'd revert forever and never move on.

THE DRIFT TO STOP (the lead kept doing this): finding "clean on-ramp / clean sequencing" reasons to HOLD a faithful mover — scope it re-entry-only, defer it behind a prereq so it lands net-positive, keep an adaptation in place to avoid a dip, "HELD-and-report if it regresses." That IS the timid gauge-protecting behavior the policy forbids. Land the faithful port; chase what it exposes.

The ONLY thing to gate on a faithful MOVER is FAITHFULNESS itself — correct port vs MIS-PORT? A mis-port regresses because the port is WRONG → fix it (never land it). A faithful port regresses because OTHER non-Ghidra code is wrong → LAND it, cite + fix that next. Measurement's role is (a) confirm faithful vs mis-port and (b) NAME what the faithful port exposed → the next task. NOT to decide land-vs-hold.

Still required (not gauge-protection, just correctness/tracking): suite green (no crashes/panics), and RECORD the exposed-gap diagnostic as the follow-up task. Byte-identical faithful ports self-approve; faithful MOVERS also land — the agent reports the delta so the lead confirms faithful + logs the exposure, then it lands. Do NOT hold it for regressing.

PRECEDENT proving the pay-off: guard_returns-persist landed net-negative (regressed noforloop_globcall/switchhide via the exposed P6 void gap) → then went net-POSITIVE once P6 (ancestorOpUse) fixed the exposed code. Same class now = guardCalls-for-ram + the proven-ready iterating mainloop: land them faithful, let the corpus dip, fix what they expose. See [[port-all-faithful-rules]], [[direction-faithful-port]].
