---
name: unlinked-zero-field-changes-the-decode
description: "A zero relocated field is not a cosmetic difference — it changes which SLEIGH constructor is selected, so byte-identical code hashes two ways"
metadata: 
  node_type: memory
  type: project
  originSessionId: 6a216fa6-e69f-4b20-b0bf-429f1307092c
  modified: 2026-08-08T23:51:48.420Z
---

**⭐ 2026-08-09 (`b678279`).** FID could not identify functions whose code was byte-identical
between an unlinked library member and the linked program. Masked bytes agreed on EVERY
instruction; the operand lists did not:

    library  MOV AL,[EAX]            ops = [Register(0)]
    WAR2     MOV AL,[EAX + 0x8ef18]  ops = [Register(0), Scalar(585496)]

**THE RULE: an unapplied relocation is not "a wrong value in a masked field". A zero displacement
selects a DIFFERENT CONSTRUCTOR — the addressing form with no displacement operand.** FID folds an
operand object per operand into the full hash, so the same function hashes two ways depending on
whether a linker has run. The identical masked bytes are what makes this so hard to see: every
byte-level comparison says the two agree.

The cause was an adaptation: our OMF loader applied only the CALL encodings it had names for
(`Near16`/`Near32`/`Far1616`), so data references vanished silently. The fix was to port Ghidra's
`OmfLoader.processRelocations` wholesale — every location type, every target method,
segment-relative as well as self-relative, plus GRPDEF and target THREADs. WAR2 **120 → 130
named, nothing lost**; hash parity unchanged 308/320.

**Why no gate caught it, and this is the transferable part:** the databases were internally
consistent, scored perfectly against themselves, and drifted from nothing. `fid_detect_versions`
scores each database against its OWN records — stale-vs-stale agrees perfectly. Only comparing
against a REAL LINKED BINARY could fail. See [[absolute-vs-differential-wrongcode]] — a defect
present on both sides of a comparison is invisible to it.

Corollary for enum design: an enum of *encodings we recognise* makes an unhandled case DISAPPEAR.
Record the raw fields and match on them, so an unhandled case is a visible arm.

Related: [[war2-crt-identified-by-omf-lib-search]], [[fid-port-track]],
[[self-compiled-gate-measures-your-imagination]].
