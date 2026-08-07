---
name: war2-relocation-seeding
description: LE fixup records seed disassembly (beyond-Ghidra) — WAR2 1631→1965, missing 496→222; the FP criterion vs Ghidra is obsolete, use body-intrusion instead.
metadata:
  type: project
---

Landed `ef98638` (+ `cd6b541` characterisation) on `analysis-port`. mosura's LE loader keeps the
linker's fixup table (`019afc5`) and seeds disassembly at every relocation target in executable
memory. **Ghidra cannot do this**: the LE→ELF wrapper it is fed bakes the patched values in and
discards the records, so it must find pointers statistically (runs), which can never see an
**isolated** pointer stored between non-pointer struct fields.

WAR2: **1631 → 1965** functions, ∩tracker 1624 → 1898, missing 496 → **222**, real-function-body
coverage 85.2% → **98.7% of Ghidra's**.

**⭐ THE MEASUREMENT RULE THAT CHANGED THE VERDICT.** "Functions not in Ghidra's set" stopped being
evidence of a defect once the tracker became the target. The number that maps to byte-exactness is
**body intrusion** — am I corrupting a function I already have:

| | not in tracker | INSIDE a known body | in gaps |
|---|---|---|---|
| mosura A+B | 67 | **3** | 64 |
| Ghidra 2145 | 120 | **106** | 14 |

Ghidra's 106 are the documented 1–5 byte Watcom prologue shift. mosura's 3 are NOT benign — they
are +37/+59/+65 bytes deep (`00010bb1`, `000604c4`, `00064c1c`; two shared with Ghidra) and are
extent-corruption seeds. Named in the module doc, not laundered.

**Open defect:** 7322 extra instruction starts in 255 runs (104.4% code coverage) — data decoded
as code. Two candidate discriminators are MEASURED DEAD: `mustTerminate=true`
(`isValidSubroutine`) gives byte-identical results at this scale, and the flow-disassembler
bounds (`708ac08`) do not touch it. Don't retry either.

**51 candidates in neither oracle** → `docs/war2-relocation-seed-candidates.md`, an adjudication
request for the WAR2 agent.

MVE: `oracle/ground-truth/src/lestruct.c` → `lestruct.watcom-le`, the corpus's first **Linear
Executable** (`wlink format os2 le`; truth from wlink's MAP + LE object bases, matching on the
symbol's OFFSET because the LE image is pre-relocation). The obvious MVE (`datafnptr` rebuilt as
LE) PASSES unfixed — see [[mve-obvious-version-tests-nothing]].

See [[war2-address-table-port]], [[ghidra-never-makes-functions-from-data-pointers]].
