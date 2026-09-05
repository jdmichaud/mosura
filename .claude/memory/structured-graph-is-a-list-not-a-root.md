---
name: structured-graph-is-a-list-not-a-root
description: "⭐ LANDED 2026-07-30 (282bf51/b3afd4d): a collapse that cannot reduce to ONE node is NORMAL in Ghidra — emitBlockGraph prints every top-level component. mosura emitted only the entry's and silently dropped 45 basic blocks across 10 the subject functions. reached==cfg 45→0, undefined labels 18→0, call deficit 10→4 (EMITTER side 0), COMPILE_FAIL 102→95, byte-clean unmoved at 15."
metadata: 
  node_type: memory
  type: project
  originSessionId: 99103a08-9d06-430b-8446-4ca5e3757106
  modified: 2026-07-30T13:29:11.852Z
---

Ghidra's collapsed structure is a **list**, not a root. Three independent places say so:

- `CollapseStructure::collapseAll` (blockaction.cc:1877) stops at `isolated_count < graph.getSize()`,
  with `getSize()` = `list.size()` — it does not require one node.
- `BlockGraph::orderBlocks` (block.hh:430) guards its sort with `if (list.size()!=1)`.
- `PrintC::emitBlockGraph` (printc.cc:2746, reached from printc.cc:2660) loops over `getList()`.

mosura modelled the result as a single `root` and emitted only that, so every other component
vanished — 45 basic blocks in 10 the subject functions, including live CALLs, while sibling components kept
jumping to labels inside them. Now `Structured::roots` holds Ghidra's list, ordered by
`compareFinalOrder` (block.cc:709; entry index 0 first, RETURN-terminated last, else by index, where
a composite's index is the MIN over its components per `addBlock`, block.cc:862).

**Blast radius is exactly those 10 functions and provably so** — components are disjoint, so
multi-root ⟺ blocks unreached by the tree.

A second mis-port surfaced the moment the components were emitted: an unconditional cut edge was
keyed on `exit_basic(source)`, but Ghidra's `newBlockGoto` (block.cc:1702) wraps the whole SOURCE
NODE so `emitBlockGoto` prints the body and then the goto AFTER it. Equivalent for a leaf and a
`List`, WRONG for an `If` whose exit basic block sits inside the then-arm — the goto got buried and
the other path fell off the end of a non-void function. Fixed by keying unconditional cuts on the
structured-node index (`node_gotos`); conditional `BlockIfGoto` cuts correctly keep the block key.

Measured 5d517ee → 17666ad: reached==cfg 10 fns/45 blocks → 0/0 · undefined-label 18 → 0 ·
falls-off-end 1 → 0 · absolute call deficit 5 fns/10 calls → 1 fn/4 calls with the EMITTER layer 6 → 0
(00079130 is the lone genuine recovery gap) · 0 functions lose a call · COMPILE_FAIL 102 → 95 ·
corpus 0.9534/58 unchanged · suite 496/0.

⚠️ **BYTE-CLEAN DID NOT MOVE: 15 → 15 with an IDENTICAL member set.** No multi-block function became
byte-exact, so the campaign milestone in [[first-exact-lane]] is still open. Emitting the lost blocks
was necessary for it, not sufficient — the whole gain is 7 functions that now compile.

The defect had been misdiagnosed three times because of [[oracle-same-question-not-just-same-tool]];
commit 7e14035 had explicitly killed this exact hypothesis on a graph Ghidra only had because it
deleted live code.

Related: [[gauge-counting-traps]], [[print-raw-has-no-dead-filter]], (subject-profile note `byte-exact-campaign`).
