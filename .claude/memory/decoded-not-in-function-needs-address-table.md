---
name: decoded-not-in-function-needs-address-table
description: "To gate the above-function guard you need code that is DECODED but in NO function — only AddressTableAnalyzer produces that state, and the compiler flag is what makes the gate able to fail."
metadata: 
  node_type: memory
  type: project
  originSessionId: df001909-493d-4f50-92ac-53ef8ca6337d
  modified: 2026-08-06T15:57:26.392Z
---

Gating anything in `check_already_in_function_above` needs a rare state: an instruction that is
**decoded but belongs to no function**. Two attempts to build it failed before the mechanism was
identified (`4665c2b`, 2026-08-06, fixture `oracle/ground-truth/src/retorphan.c`).

**`AddressTableAnalyzer` is the only route.** It disassembles a pointer run's targets and
deliberately creates no function at them (`AddressTableAnalyzer.java:282`). A *single* stored
pointer takes the `DataOperandReference` path and decodes nothing — which is why the first attempt
(`retboundary`) produced a gate that passed with the fix reverted: the preceding block was never
decoded, so the guard arm never ran at all. Confirm the state exists before writing fixture source:
`datafnptr.watcom-x86-32` already holds 15 decoded-not-in-a-function instructions.

**The compiler flag IS the gate.** Which prologue family matches decides which discovery path runs,
because the ESP-frame family carries `after="defined"` and frame-first does not:

| flag | orphan bytes | fix in place | fix reverted |
| --- | --- | --- | --- |
| `-oc` | `56 57 55 83 ec 14` (ESP-frame) | recovered | **NOT recovered** ✅ |
| `-of+` | `55 89 e5 …` (frame-first) | recovered | recovered ❌ vacuous |

Opposite flag choice from `fnpattern`, for the opposite reason. **Pick the flag that lets the gate
fail, and show the other side of it** — this is the concrete form of
[[could-it-have-come-out-otherwise]] for pattern fixtures.

⚠️ **The trap that mimics a broken fix:** if two handlers share a tail (`sub g_acc ; ret`), wcc386
folds them, the table's entry points offcut into the neighbour, `AddressTable.checkTable` trims the
table there, the later target is never disassembled — and the orphan is refused **even with the fix
in place**. Give each handler its own global. Verified independently (2026-08-06): reintroducing the
adjacency bug fails both the unit test and `ground_truth_parity::above_function_guard_tests_fall_through`.

See [[subregister-write-not-merged]] for the sibling class, and
[[load-the-artifact-directly]] for when a fixture cannot reach the code at all.
