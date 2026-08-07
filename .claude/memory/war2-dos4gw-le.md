---
name: war2-dos4gw-le
description: "WAR2.EXE is DOS/4GW-bound LE — stock Ghidra loads only the MZ stub, BUT warcraft2-re's ELF32 wrapper gives Ghidra full whole-image analysis; mosura reads the LE directly"
metadata: 
  node_type: memory
  type: reference
  originSessionId: 99103a08-9d06-430b-8446-4ca5e3757106
  modified: 2026-08-05T08:50:07.799Z
---

`~/WAR2.EXE` (Warcraft II) is a **DOS/4GW-bound Linear Executable (LE)**. Ghidra has no LE/LX
loader and WAR2's `e_lfanew` is deliberately invalid (Tenberry writes `0x9B40000` so DOS does
not auto-detect it), so **stock Ghidra loads only the 16-bit MZ stub** (~312 funcs).

## ⚠️ THAT IS NOT "GHIDRA CANNOT ANALYZE WAR2" — it can, whole-image

**`~/projects/warcraft2-re/tools/ghidra/make_war2_elf.py`** extracts the two LE objects (obj1
code @ `0x10000` size `0x6C4A0`, obj2 data @ `0x80000` size `0x2B300`) into a synthetic **ELF32
i386 wrapper** (`tmp/WAR2.elf`, `tmp/WAR2_reloc.elf`). Ghidra loads that cleanly as
`x86:LE:32:default` and auto-analysis finds ~1100 functions. Measured 2026-08-05:
**analyzeHeadless on `WAR2_reloc.elf` = 49.8s**, full analyzer set, JVM startup included.
Doc: `~/projects/warcraft2-re/analysis/ghidra-setup.md`.

I asserted "Ghidra can't load WAR2" to the owner on 2026-08-05 and was corrected. The claim came
from `scripts/ghidra-decompile-war2.sh`'s header plus MEMORY.md's own hook for this file, which
read "only the MZ stub loads" and dropped the wrapper half. **A lossy index line propagates as a
false belief** — the detail was right here all along and I never opened it.

## ⭐ The consequence that matters: a BETTER oracle exists

The per-function recipe ([[war2-per-function-ghidra-oracle]]) imports one function's bytes as a
raw binary, so Ghidra sees no callees and defaults them to ZERO PARAMS — its dead-code pass then
deletes registers mosura keeps live, its output looks *better structured*, and that misreading
cost three sessions ([[oracle-same-question-not-just-same-tool]]). **A whole-image ELF-wrapper
import does not have that defect**: real callees, real prototypes, real cross-function context.
The per-function workaround exists only because of the false belief above. Prefer the wrapper
for any question where callee prototypes or cross-function flow matter.

## Stale claims removed from this file (were true when written, are not now)

- ~~"mosura reports 0 functions for every binary; A4 not ported"~~ — mosura's
  `analysis::analyze_le_file` reads the LE **directly** (no wrapper) and recovers **1303
  functions**, more than Ghidra's ~1100 on the wrapper.
- ~~"getting WAR2's code into mosura needs 32-bit ELF support + the extraction step, not an LE
  loader"~~ — mosura took the LE-loader route and it works ([[war2-le-fixups-root-cause]]).

Related: [[war2-recompile-survey]], [[war2-survey-artifacts-stamped]].
