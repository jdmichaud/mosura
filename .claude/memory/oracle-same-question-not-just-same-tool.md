---
name: oracle-same-question-not-just-same-tool
description: "⭐ READING GHIDRA'S OUTPUT IS NOT ENOUGH — verify Ghidra was ASKED THE SAME QUESTION. The per-function oracle defaults absent callees to zero parameters, so its dead-code pass deletes registers mosura keeps live; the two sides then decompile DIFFERENT functions and any structuring comparison between them is void."
metadata: 
  node_type: memory
  type: feedback
  originSessionId: 99103a08-9d06-430b-8446-4ca5e3757106
  modified: 2026-07-30T13:28:53.050Z
---

Rule Zero says read Ghidra's output for the specimen before theorising. This is its necessary
second half, bought with a three-pass misdiagnosis of the subject's `FUN_00077dcb` (2026-07-30).

The per-function oracle ((subject-profile note `per-function-ghidra-oracle`)) imports only the requested function's
bytes, so every callee's prototype falls back to the database default — **no parameters**. Ghidra's
dead-code pass then deletes every register the callee "does not read". On `FUN_00077dcb` that killed
EDX, which deleted `xor %edx,%edx` and an entire comparison, which left Ghidra with 6 basic blocks
and a clean `while` where mosura (whole-program, EDX live) had 8 blocks and 3 gotos.

Three sessions read that as a mosura structuring defect and hunted CFG granularity, `is_complex`,
`select_goto` scoring and the collapse termination test. All four were faithful. **The graphs were
never comparable.** Adding the callees to the import does not fix it either — prototypes still
default unless the callee function exists BEFORE the caller is decompiled, and even then Ghidra does
not commit a recovered prototype.

**How to make the comparison valid** — `oracle/ghidra_scripts/DecompileWithForcedParams.java`
forces a callee's parameter storage, so both sides see the same liveness:

```sh
GHIDRA_POSTSCRIPT=DecompileWithForcedParams.java GHIDRA_POSTSCRIPT_ARGS='63c35=EDX' \
  scripts/ghidra-decompile-subject.sh 63cbf 722c8 63c35 77dcb   # callees FIRST — created in list order
```

With the graphs made comparable, Ghidra produced mosura's partition block-for-block AND three gotos
of its own, and the entire real defect was one unported line: `PrintC::emitBlockGraph` (printc.cc:2746)
loops over every top-level component and mosura emitted only the first.

**Generalization:** before attributing any difference to the decompiler, check that the oracle had
the same inputs — callee prototypes, calling conventions, reachable code. `scripts/ghidra-decompile-subject.sh`
already warns that missing context makes Ghidra PRUNE LIVE CODE; the trap is that pruning is silent
in the direction that makes Ghidra's output look *better structured*, so it reads as our bug.
Companion instruments: `MOSURA_CFG=1` (mosura's partition) vs `DumpBlocks.java` (Ghidra's).

Related: [[absolute-vs-differential-wrongcode]] (a defect on both sides is invisible),
[[trace-diff-first-not-fifth]], [[numbers-stale-unless-sha-stamped]].
