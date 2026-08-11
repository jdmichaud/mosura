---
name: war2-crt-identified-by-omf-lib-search
description: warcraft2-re named 161 Watcom CRT functions in WAR2.EXE with a bespoke OMF .LIB masked-byte search — NOT Ghidra FID; its 152 crt-known tracker rows are free ground truth
metadata: 
  node_type: memory
  type: project
  originSessionId: 6a216fa6-e69f-4b20-b0bf-429f1307092c
  modified: 2026-08-07T13:32:18.995Z
---

**How `../warcraft2-re` identified stdlib/CRT functions in the Watcom-compiled `WAR2.EXE` — and
why it is NOT a counter-example to "Ghidra ships no Watcom FID DB".**

**It did not use FID.** Zero references to FID / `.fidb` / FLIRT anywhere in that project.
Ghidra's FID analyzer does run in auto-analysis, but with only MSVC DBs loaded it says nothing
about a Watcom binary. So the agent wrote its own: `tools/ghidra/identify_crt.py`, **978 lines of
Python**, documented in `analysis/crt-identification.md`. Method: parse the Watcom 10.0a OMF
`.LIB` (CLIB3R/MATH387R/CPLX3R) → rebuild `_TEXT` from LEDATA/LIDATA → **mark FIXUPP-touched
bytes as wildcards** (relocation mask) → slice bodies by PUBDEF offset → longest unmasked run
(≥6 B) as a search anchor → verify whole body modulo mask in WAR2's code region → push names via
Ghidra MCP. **161 unique matches**, 175/533 CLIB3R publics, 3 ambiguous, 3 collapsed.

**The 978 lines exist BECAUSE nothing shipped for Watcom** — same gap [[fid-port-track]] §4
describes. It VALIDATES the FID plan:
- its founding premise (CRT bytes in WAR2 are **byte-identical** to the `.LIB` bodies, same
  toolchain) is exactly Stage 7's Watcom premise, now demonstrated on the real target;
- its signature source (the OMF `.LIB`) is exactly what Stage 6 ingest consumes. mosura already
  walks OMF LEDATA/LEDATA32 (`scripts/extract-omf-code.py`); Stage 6 additionally needs
  PUBDEF/SEGDEF/FIXUPP.

**Where FID beats it — precisely at that tool's reported gaps:** 3 ambiguous
(`__STKOVERFLOW_` 5 hits, `__sigabort_` 8, `itoa_` 2) + 3 va-args trampolines collapsed to ONE VA
(`sscanf_`/`fscanf_`/`fprintf_`, 33 B differing only in a masked `call` target) — these are what
**relation scoring** (`forceRelation`, parent/child code-units) is built for. Also: 30 bodies had
"no usable anchor" and 71 were "too short" — a contiguous ≥6 B literal run is brittle; FID hashes
the whole masked stream with a 4-code-unit floor. Where IT wins: for one known-version target it
needs no DB at all.

**⚠️ SHARED BLIND SPOT:** compiler-emitted intrinsics (`__I8RS`, `__U8D`, `__I8M`, 386 codegen
helpers) come from `wcc386` straight into each user `.OBJ`, never from a library — no `.LIB`
ingest finds them, FID included. Route = ingest a **self-compiled** program that provokes them
([[self-compiled-ground-truth]]).

**⛔ USER RULE 2026-08-07 — do NOT gate on any of this.** Two parts: (a) **`WAR2.EXE` is barred
from mosura's official verification** — it is a user-supplied binary that can go away at any
time, so no test may depend on it; it is a **development guide** and **post-release validation**
only. (b) **Treat all warcraft2-re data with a grain of salt** — its numbers come from a
byte-search heuristic with documented failure modes (ambiguous hits, collapsed trampolines, a
≥6 B anchor floor); a lead for orientation, never load-bearing. Anything worth keeping gets
re-derived from a source we own. I proposed gating Stage 7's Watcom column on its 152
`crt-known` rows and was corrected — the gate is **self-compiled** instead (we own source +
toolchain + link, so the expected name set comes from our own build).

What survives is the **mechanism knowledge**, which is the valuable part: OMF `.LIB` →
PUBDEF-sliced bodies → FIXUPP-masked bytes is the shape of the Watcom signature source.
