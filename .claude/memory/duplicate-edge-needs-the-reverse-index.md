---
name: duplicate-edge-needs-the-reverse-index
description: A CBRANCH whose two targets are the same block duplicates a CFG edge; matching phi slots by predecessor instead of by edge leaves one slot unwired forever
metadata: 
  node_type: memory
  type: project
  originSessionId: 6a216fa6-e69f-4b20-b0bf-429f1307092c
  modified: 2026-08-09T09:07:32.563Z
---

**⭐ 2026-08-09 (`0fe543a`) — the cause of heritage's non-termination.**

A CBRANCH whose taken and fall-through targets are the **same block** gives that block a
DUPLICATED in-edge (`blk 2 out_edges=[3,3]`, `blk 3 in_edges=[1,2,2]`), and its MULTIEQUAL one
input per EDGE — two of them from that one predecessor. Our rename wired them with

    let j = blocks[s].in_edges.iter().position(|e| e == b).unwrap();   // FIRST match

so the successor loop visited the duplicated edge twice, computed slot 0 both times, wrote it
twice, and **never wrote the later slot at all**. Its input kept the free placeholder, the
location never became heritage-known, its range re-entered `disjoint` every pass, and
`guard_calls` added another INDIRECT per call per pass — the graph grew without bound and
`heritage_complete` could never be true.

**THE RULE: index phi slots by the EDGE, not by the predecessor block.** Ghidra stores a reverse
index per edge (`FlowBlock::getOutRevIndex(i)`, heritage.cc:2533). Our blocks keep plain
`Vec<BlockId>` lists with no reverse index, so pair the k-th duplicate out-edge with the k-th
matching in-edge — CFG construction appends both lists in the same order.

⚠️ **Do NOT "fix" `branch_remove_internal` by symmetry.** Its `position()` looks like the same
bug, but Ghidra's `branchRemoveInternal` (funcdata_block.cc:207) uses `getInIndex(bb)`, a
first-match lookup too — that line is already a faithful port.

⚠️ **The corpus cannot see this** (byte-identical before and after): no x86-64 datatest has a
duplicated edge. The regression test `duplicate_edge_fills_every_phi_slot` was checked BOTH ways.
Its first version was VACUOUS — with a single predecessor the join is dominated by it, no phi is
placed, and the assertion ran over an empty set. It needs two distinct predecessors, one of them
duplicated, plus an explicit `assert!(phis > 0)`. See
[[gate-what-you-measured-not-what-you-guessed]] and [[could-it-have-come-out-otherwise]].

Related: [[structured-graph-is-a-list-not-a-root]], [[heritage-core-campaign]].
