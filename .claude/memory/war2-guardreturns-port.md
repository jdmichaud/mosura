---
name: war2-guardreturns-port
description: "6e1b113 — return candidates now come from the cspec via Heritage::guardReturns, not hardcoded RAX/XMM0; moved the WAR2 byte-exact headline 1 → 9 and closed the narrow-switch bug."
metadata: 
  node_type: memory
  type: project
  originSessionId: 99103a08-9d06-430b-8446-4ca5e3757106
  modified: 2026-07-29T13:21:16.568Z
---

`6e1b113` (2026-07-29) retired `recover_return`'s hardcoded x86-64 `RAX:8`/`XMM0:8` candidates,
appended pre-heritage to every RETURN, in favour of Ghidra's real mechanism: `initActiveOutput`
(funcdata_varnode.cc:585) opens an EMPTY trial container pre-heritage and `Heritage::guardReturns`
(heritage.cc:1652) asks `FuncProto::characterizeAsOutput` of EVERY heritaged range, registering one
trial + one RETURN input on containment (`guardReturnsOverlapping`, heritage.cc:1609, on
`contained_by`). Commit is `deriveOutputMap` + a faithful `buildReturnOutput` (coreaction.cc:1837).
Needed two partial ports completed: `ParamTrial::setEntry`/clear in `derive_output_map` and the
entry-less-sinks-last rule in `sortTrials` (fspec.cc:1894).

**Results.** Byte-clean WAR2 functions **1 → 9** (5 EXACT + 4 RELOC_EXACT of 1303) — the headline's
first movement in weeks. Absolute call gauge 3705 → 3867 sites (94.8% → 98.9% of Ghidra); deficit
92 fns/246 calls → 29 fns/87 calls, the new set a STRICT SUBSET (0 newly deficient). 17 more
functions discovered. Corpus 0.9535 → 0.9426 (3 fixtures up, mixfloatint down).

**It closed `docs/decompiler-bug-narrow-switch.md`.** `JumpBasic` was never at fault: on x86-32 the
`RAX:8` candidate is an 8-byte read at register offset 0 spanning EAX *and* ECX, a range nothing
writes. It forced a spurious heritage location whose batch read-normalization rewrote the narrow
accesses to EAX, severing the switch guard's `SUBPIECE(x,0)` from the table index's
`INT_AND`/`INT_ZEXT`. Verified causally — re-adding that one read reopens the gap. All four WAR2
sites the doc predicted now recover (dispatch sites 8 → 12).

**Two residuals, both diagnosed, neither a mis-port:**
- `mixfloatint` 0.967 → 0.235: the merged-disjoint-cover gap. Ghidra work-lists the MERGED range
  (heritage.cc:2710) so XMM0's two PreferSplit lane writes plus the 8-byte read are ONE trial;
  mosura's per-varnode cover (heritage.rs:1648 keeps `loc`, discarding the merged extent) registers
  two lane trials that `onlyOpUse` (funcdata_varnode.cc:1849) then rejects against each other. This
  is task #6 / [[subregister-write-not-merged]].
- `FUN_0006af2c` −18 calls: the ONLY wrong-code function. Its 10-target jump table recovers FULLY
  and `switchnorm` folds the BRANCHIND correctly, then the CFG is torn down to 1 block / 18 ops /
  no edges. Isolated — the other three functions owning newly recovered narrow switches keep 26/15/19
  blocks. (`FUN_00051298` −10 is a SEPARATE defect: 26 blocks, table recovered, calls still dropped.)
