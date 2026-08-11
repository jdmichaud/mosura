---
name: dead-ops-stay-in-our-block-lists
description: "Ghidra's opDestroy removes an op from its basic block; mosura leaves it in BlockBasic::ops marked dead with no inputs, so every port of a block-op walk needs an explicit dead filter"
metadata: 
  node_type: memory
  type: project
  originSessionId: 6a216fa6-e69f-4b20-b0bf-429f1307092c
  modified: 2026-08-09T09:22:03.180Z
---

**⭐ 2026-08-09 (`a4081da`).** A representation difference that silently breaks faithful ports:

- **Ghidra:** `opDestroy` REMOVES the op from its basic block (it moves to the dead list). Any code
  walking `bl->beginOp()..endOp()` therefore sees only LIVE ops.
- **mosura:** a destroyed op stays in `BlockBasic::ops`, marked dead, **with its inputs cleared**.

So a line-for-line port of a block-op walk is NOT faithful: it visits ops Ghidra never would. In
`branch_remove_internal` / `block_remove_internal` this meant `op_remove_input` on an op with no
inputs — `removal index (is 1) should be < len (is 0)`. Open Watcom's `signl.c` carries five dead
phis in the block whose duplicated edge is removed.

**THE RULE: when porting anything that iterates a block's ops, filter `!f.op(op).is_dead()`** —
that filter IS the port of Ghidra's list membership, not an extra safety check. Same shape as
[[print-raw-has-no-dead-filter]] (`print_raw` lists DESTROYED ops as bare opcodes, so corpses read
as live).

⚠️ The corpus cannot see this (byte-identical): its x86-64 datatests never reach the shape. The
regression test `redundbranch_ignores_destroyed_multiequals` is the only coverage, and it asserts
UP FRONT that the destroyed phi is still in the block list — so it cannot quietly stop biting if
the representation is ever changed to match Ghidra's.

Found alongside [[duplicate-edge-needs-the-reverse-index]], which had masked it.
