---
name: ghidra-never-makes-functions-from-data-pointers
description: "Ghidra's data-side analyzers DISASSEMBLE pointer targets and deliberately create NO function there; functions arrive from the direct calls inside the newly decoded code."
metadata: 
  node_type: memory
  type: project
  originSessionId: df001909-493d-4f50-92ac-53ef8ca6337d
  modified: 2026-08-05T13:56:33.738Z
---

Ghidra reaches code that is only referenced from data by **disassembling** it, never by
creating a function at the pointer target. Three separate places say so in the source:

- `AddressTableAnalyzer.processAddressTable` (:282-296) builds `validFuncSet` and leaves the
  `mgr.createFunction` call **commented out** — *"For Now, Never make functions from address
  tables"*.
- `OperandReferenceAnalyzer.createFunctions` (:614) is an empty body — *"don't ever create
  functions from pointed to code"*.
- `DataOperandReferenceAnalyzer.createFunctions` (:39) likewise.

The functions appear afterwards, the ordinary way: `FunctionAnalyzer` ("Subroutine References",
`plugin/core/function/FunctionAnalyzer.java:49`) creates one at every **direct-call target
inside** the newly decoded code. So the fix for a data-reachable subgraph is a
DISASSEMBLY-COVERAGE fix, and its yield is the cascade, not the pointer targets themselves.

**Why this matters and gets re-derived wrongly:** the obvious reading of "port the data-reference
analyzer so we find the missing functions" is "make a function at each pointer target". That
would destroy the 0-false-positives-vs-Ghidra property. Verified empirically on
`oracle/ground-truth/datafnptr.watcom-x86-32`: Ghidra decodes all four handlers behind the
pointer table, creates **no** function at any of them, and does create the helper one of them
calls. mosura now matches exactly.

Consequence for gates: `ground_truth_parity`'s nm-derived recall list will name the pointer
targets as functions (the compiler knows they are). They carry a documented, program-scoped
carve-out; the real property is gated by `ground_truth_parity::data_pointer_function_discovery`.

See [[war2-address-table-port]], [[war2-missing-calls-class]],
[[oracle-same-question-not-just-same-tool]].
