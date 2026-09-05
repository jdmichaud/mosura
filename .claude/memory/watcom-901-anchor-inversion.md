---
name: watcom-901-anchor-inversion
description: "Watcom 9.01 emits SETcc;MOVZX and MOV r,imm;CDQ;IDIV — the two shapes the repo treated as Open-Watcom-only. They mark the lineage's OUTER ENDS, not Open Watcom."
metadata: 
  node_type: memory
  type: project
  originSessionId: df001909-493d-4f50-92ac-53ef8ca6337d
  modified: 2026-08-06T15:57:43.312Z
---

Adding Watcom **9.01** (1992) to `oracle/codegen-probes/watcom/` (`fa6794d`, 2026-08-06) did not add
a row — it **inverted a claim**. 9.01 emits *both* shapes the repo used as Open-Watcom evidence:
`SETcc ; MOVZX` and `MOV r,imm ; CDQ ; IDIV r`.

So neither shape marks Open Watcom. They mark the lineage's **outer ends**, and the surviving fact
is narrower: the classic **interior** (10.0a / 10.6 / 11.0) emits neither. Verified independently by
byte-counting all five committed `.code` artifacts:

```
          setcc(0f9x)  movzx(0fb6)  and-eax-ff  cdq(99)
  9.01         1            1            0          1     <- outer end
  10.0a        1            0            2          0
  10.6         1            0            1          0     <- interior
  11.0         0            0            0          0
  ow2          1            1            0          1     <- outer end
```

`identify_watcom_program` now reports `{watcom:9.01, watcom:open}` where it said `watcom:open` —
**less precise and correct**. What separates the two is the loop register and switch order, the
artifacts that whole-binary scale drops by design.

**the subject is unaffected and its anchor gets stronger:** the subject keys on the *promoting* `cmp eax,5`, which
is 10.0a's alone. 9.01 showing a plain byte compare makes the promotion a **one-revision anomaly
with plain compares on both sides**, not "early Watcom" behaviour.

Two pre-existing defects found while measuring the control column:
- **11.0's `cmpbyte` doc row said `cmp al,5 ; sete al`; its object contains no `setcc` at all**
  (verified: count 0). It is `cmp al,5 ; jne ; mov eax,1`. Its TABLE row still claims
  `Some(false)` — unevidenced, and would exclude 11.0 from any binary showing `SETcc ; MOVZX`.
  Left unchanged deliberately rather than edit a matcher row to match a hypothesis.
- **`result_zero_extended` means `MOVZX` specifically, not zero-extension.** 10.0a and 10.6 *do*
  zero-extend — with `AND EAX,0xff`. Broadening the detector to accept the `AND` form would flip
  both to `Some(true)` and collapse the table's only discriminator between interior and outer ends.

⚠️ Keep this axis apart from the **entry-shape** axis, which is closed: 9.01 differs from 10.0a by
6 bytes on the prologue probe, all SIB base/index swaps inside bodies, zero in any prologue
(see the §5 cell 6 table). Body codegen separates the revisions; entry shape never does.
Related: [[generated-artifact-drift]], [[invention-worse-at-its-own-job]].
