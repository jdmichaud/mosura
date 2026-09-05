---
name: scan-set-readd-by-next-function
description: "SharedReturnAnalysisCmd deletes a contiguous function's body from jumpScanSet, then the NEXT function's checkAboveFunction adds it straight back — so two adjacent functions in one set resurrect the source."
metadata:
  type: reference
---

`SharedReturnAnalysisCmd` builds `jumpScanSet` from two halves that **fight each other**:

```java
checkBelowFunction  :327  if (body.getNumAddressRanges() <= 1) jumpScanSet.delete(body);
checkAboveFunction  :304  jumpScanSet.addRange(prevFunction.getEntryPoint(), fnAddr);
```

The delete removes a *contiguous* function's own body — but `checkAboveFunction` for the
**next** function adds `[prevFunction.entry, fnAddr]`, which spans that same body and puts it
back. So a contiguous function's interior is scanned **iff its successor is in the same
`set`**. Reading either half alone gives the wrong answer.

## Measured (2026-08-10, the `1d74e` regression, reverted at `b2de9e8`)

the subject MZ, `FUN_0001d76a` body `1d74e:1d790` (single range, contains the `EB C0` at `1d78c`):

```
set = 140 fns, ∩window = [1d678 1d76a 1d7b5 1d7ba 1d7f6]   scan.contains(1d78c) = true
  without 1d7b5 -> false      <- uniquely 1d7b5
  without any other -> true
  singleton {1d7b5} -> true   <- FINER GRANULARITY DOES NOT HELP
```

**The consequence that matters: you cannot fix this by shrinking the batch.** A per-function
loop still delivers `1d7b5` on its own and still resurrects `1d78c`. Anyone who reasons "make
the invocation finer, like Ghidra's" without measuring the singleton will re-land the same bug
— see [[command-queue-modelled-as-change-channel]] for where the real fix lives.

⚠️ And the shape to carry: a function body whose **minimum is below its own entry** is normal
in Ghidra (`fnbody 0001d76a 0001d74e:0001d790`) — a backward jump pulls earlier code in. Such
an address is INTERIOR, not a function Ghidra declined to create. Reading it as a missing
function inverts the entire diagnosis, which is what happened here for two sessions.
Related: [[pspec-key-differs-from-java-field]], [[shared-return-cursor-cache-is-semantic]].
