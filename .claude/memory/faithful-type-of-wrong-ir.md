---
name: faithful-type-of-wrong-ir
description: "An ugly render (xunknownN / spurious cast) from a FAITHFUL printer/rule = the faithful type of WRONG upstream IR. Fix the IR, never strengthen downstream type-inference/printer to hide it (= inventing a non-Ghidra heuristic). Symptom-level task framings are often mis-attributed — instrument-first before coding."
metadata:
  node_type: memory
  type: feedback
  originSessionId: c0fe6b35-0fb2-4ed2-90d8-ec93de63680c
---

p4infer1 grounding #13/#14 (the isSubpieceCast −0.028/−0.012/… dips), 2026-07-11: the `(xunknownN)`/`(uintN)` casts are the FAITHFUL type of IR VALUES THAT SHOULDN'T EXIST — a 16-byte XMM value (should be 8-byte lanes = LaneDivide, [[task6-lanedivide-plan]]), an over-recovered RAX return (P6, [[task2-p6-prototypes-plan]]), an 8-byte switch accumulator (task #4, [[switchloop-dup-propagatecopy]]), a merged-phi bool (structural for-loop/array).

**THE RULE:** when a faithful printer or rule renders something ugly (`(xunknownN)`, a spurious cast, a redundant statement), the fix is the UPSTREAM wrong IR — NOT strengthening the downstream (infertypes / the printer) to type it prettily. Strengthening the downstream to MASK wrong upstream IR = inventing a non-Ghidra heuristic = the exact adaptation class the mission forbids ([[faithful-ports-land-not-held]], [[port-all-faithful-rules]]). The faithful downstream is doing its job by rendering the ugly truth; the ugliness is the DIAGNOSTIC pointing upstream. Follow it to the real subsystem.

**COROLLARY:** a symptom-level TASK FRAMING (e.g. "#13 = P4 type-inference gap") derived from the surface render is often MIS-ATTRIBUTED. Instrument-first (IR-diff mosura vs Ghidra at the site) BEFORE writing code — the dip usually belongs to an already-tracked held/gated subsystem, not the layer where it's visible. This session alone, instrument-first re-framed FOUR lead-authored task premises (#8 keystone already-landed, #10 already-landed, #12 printer-not-P4, #13/#14 upstream-not-infertypes). The lead's symptom framing is a hypothesis; the trace is the authority. See [[direction-faithful-port]].
