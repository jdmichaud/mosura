---
name: war2-le-fixups-root-cause
description: "WAR2 native-LE switch recovery + unreached decompressor both root-cause to unapplied LE fixups in loader/le.rs; the fix is loader-side, decompiler needs no change."
metadata: 
  node_type: memory
  type: project
  originSessionId: df001909-493d-4f50-92ac-53ef8ca6337d
  modified: 2026-07-20T16:38:12.785Z
---

Task #2 (WAR2 `--le` "do better than Ghidra" switches). **Phase-1 diagnosis (2026-07-20,
byte-level grounded from WAR2.EXE's own LE relocation records — NOT Ghidra, NOT the RE):**

**Single root cause: `loader/le.rs:120 load_le` never applies LE fixups.** It maps objects
+ entry but never reads the Fixup Page Table (LE+0x68) / Fixup Record Table (LE+0x6c). WAR2
has 17517 internal type-7 (32-bit offset) fixups; all unapplied. This ONE gap explains both
task symptoms:
- **cs:-relative jump tables unresolved.** `jmp CS:[reg*4 + disp32]` (`2e ff 24 8d ..`). The
  disp AND every table entry are fixup sources that relocate by +obj1_base(0x10000).
  Decompressor dispatches: `0x795d5` disp 0x694d0 → RELOC table **0x794d0** → 4 targets
  0x795e0/0x79cb0/0x7a400/0x7a4a0; `0x7a7d5` disp 0x6a6d0 → table **0x7a6d0** → 4 targets
  0x7a7e0/0x7af10/0x7b6c0/0x7b7b0. Unrelocated, mosura's flat CS reads the wrong (base-low)
  table → garbage. NOT a segment-base modeling problem.
- **Decompressor unreached** (fn_79130/793e0/7a5b0: 0 refs, undiscovered; only callers are
  E8-rel32 sites in an undiscovered gap ~0x62xxx). The subtree is gated behind cs: switch
  cases mosura never discovers because their tables are unrelocated.

**Proof:** applied all 17517 fixups to a scratch image + recursive-descent from `_cstart_`:
541 funcs / 0 switches WITHOUT fixups → **1296 funcs / 17 BRANCHIND / 103 switch targets**
WITH, and all six target addrs reached. (`examples/war2_switch_probe.rs`,
`war2_fixup_experiment.rs` — throwaway grounding, uncommitted.)

**Boundary: 100% analysis/loader-side.** Port LE/LX fixup-record application into
`loader/le.rs` (faithful spec port; mirrors Ghidra's ELF/PE relocation-at-load). Only the
`--le` path; default MZ/Ghidra-parity goldens untouched. **Decompiler + sleigh need NO
change** — post-fixup the dispatch is the standard `LOAD(ram, table+idx*4); BRANCHIND`
(JumpBasic, already green); the `2e` CS prefix is a correct no-op once the base is baked in.
So the "hard cs:-inline-table shape" worry dissolves — no decompiler handoff.

**Status: ✅ LANDED `cbd6295` (analysis-port).** `load_le` now applies the LE fixups
(`apply_le_fixups`, le.rs: Fixup Page Table LE+0x68 + Fixup Record Table LE+0x6c, internal
32-bit-offset records → reloc_base+target_off). Result: funcs 541→**1279**, **40 COMPUTED_JUMP
from 8 dispatches** (0 unmapped/spurious), decompressor discovered, both decode-loop dispatches
resolve EXACTLY (0x795d5→{795e0,79cb0,7a400,7a4a0}; 0x7a7d5→{7a7e0,7af10,7b6c0,7b7b0}). Gate:
`le_war2_analysis` (tests/analysis_parity.rs) asserts the clean subset. Only `--le` path changed
— default MZ goldens byte-identical, decompiler byte-exact (workspace 472+16 green, clippy 0).
`warcraft2-re` RE dir is EMPTY on disk — ground truth = the binary's own fixup records.
See [[war2-dos4gw-le]], [[direction-analysis-port]].

**Open follow-ons (honest partial recall):** only 8 of 17 BRANCHIND recovered as COMPUTED_JUMP;
the other 9 (register-indirect `ff e0` jmp eax + shapes JumpBasic didn't bound) are unrecovered
but 0-spurious. `apply_le_fixups` handles only internal 32-bit-offset (type-7) fixups —
imports/selectors/self-relative/16-bit unhandled (WAR2 has none; needed for other LE binaries).
