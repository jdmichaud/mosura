---
name: war2-tracker-anchors-mid-prologue
description: "The warcraft2-re tracker records save-first functions at the `push ebp`, mid-prologue — score against it SHIFT-TOLERANTLY or overstate the gap by 50."
metadata: 
  node_type: memory
  type: project
  originSessionId: df001909-493d-4f50-92ac-53ef8ca6337d
  modified: 2026-08-06T09:59:54.129Z
---

**The expert tracker's entry address is not always the function's entry.** For save-first functions
it is frequently the `push ebp` — MID-PROLOGUE, with the callee-save run before it. This is the
same `push ebp`-anchoring artifact `warcraft2-re/analysis/function-boundary-correction.md`
documents and corrected for 132 rows; **50 further rows the correction pass missed** were found on
2026-08-06.

```
mosura 0001380c [53 51 52 56 57 55 89 e5]   tracker 00013811   delta 5
mosura 000142e8 [53 51 52 55 89 e5 81 ec]   tracker 000142eb   delta 3
```

**Score a function as recovered when mosura has an entry 1-7 bytes BEFORE the tracker's with a
save-first run between them.** Naive equality on entry addresses gives 92 missing; shift-tolerant
gives **42**, i.e. 2078/2120 = 98.0% @ `556cdb3`.

**Why it matters beyond the number:** the 50 were all "inside a mosura body, zero in open space",
which read as a mechanism fingerprint and produced a whole backlog item (bodies over-extend) plus
three candidate root causes, all consistent with the evidence and none of them the cause — there
was no defect. **A DISTRIBUTION can be a measurement artifact just as a count can**, and
consistency with the evidence is not causation. See [[could-it-have-come-out-otherwise]] and
[[absolute-vs-differential-wrongcode]].

**How to apply:** never quote a WAR2 miss count without saying which comparison produced it; when a
miss set has a suspiciously clean distribution, dump the BYTES at the boundary before believing a
mechanism. mosura being at the true entry here is a consequence of the save-first pattern family
([[pattern-gate-cspec-routing]] covers gating that file) — i.e. mosura is more correct than its
oracle on these rows, and the 50 are being handed back to warcraft2-re.
