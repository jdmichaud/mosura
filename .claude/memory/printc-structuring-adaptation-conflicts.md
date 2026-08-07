---
name: printc-structuring-adaptation-conflicts
description: "Class of non-faithful adaptations: mosura does Ghidra's IR-normalization work at print/structuring time; faithful IR-rule ports expose them and land HELD until the adaptation is cancelled. Phase 1c entry."
metadata:
  node_type: memory
  type: project
  originSessionId: c0fe6b35-0fb2-4ed2-90d8-ec93de63680c
---

Discovered 2026-07-05 during the Phase 1b oppool1 tail burn-down (tail3): several remaining faithful IR rules are NOT byte-neutral — they are **movers that expose a class of pre-existing non-faithful adaptations** where mosura performs Ghidra's IR-normalization job at PRINT or STRUCTURING time instead of via the IR rule. Each such rule was landed HELD defined-but-unwired (inert, byte-identical) pending the adaptation cancel.

Known members of the class:
- **RuleSubNormal (#81, HELD `d8c924f`)** — pulls SUBPIECE back through INT_RIGHT/SRIGHT, producing a nonzero-offset SUBPIECE. mosura's printc renders `SUBPIECE(V,k)` k>0 as `(int4)V` (low bits), dropping the offset → high-word extracts print wrong (packstructaccess/impliedfield regress). Wiring it also banks a real win: ifswitch magic-division `(int4)param_1 / 5`. UNRESOLVED CONTRADICTION to settle by instrument (oracle IR dump): Ghidra's RuleSubNormal traces to also emit `SUBPIECE(x,6)`, yet Ghidra's opSubpiece (printc.cc:843) renders a non-cast subpiece via opFunc = `SUB(x,6)`, while the oracle prints `(int2)(x>>0x30)` — neither matches. Dump packstructaccess oracle IR to learn whether Ghidra keeps SUBPIECE(x,6) (→ printer port) or a shift+offset-0 truncation (→ mosura over-fires, needs a guard). See [[direction-faithful-port]].
- **RuleIntLessEqual (#10, HELD `dd6d48b`)** — faithful `replace_lessequal` converts `x<=c` to SLESS early in the IR. mosura instead does `x<=c => x<c+1` NON-FAITHFULLY at PRINT time (printc::incr_in_width) while keeping SLESSEQUAL in the IR, and its structuring/condition-negation is tuned to the SLESSEQUAL form → wiring the IR rule regresses concat/condconst/condmulti/condsplit into `x==c || x<c` disjunctions. 63 firings.

- **stackvars pre-pool spill resolution (named 2026-07-06, rock1 impliedfield instrument)** — a third
  class member, this time IR-side: mosura resolves stack spill/reload BEFORE the rule pool (its own
  stackvars pass) where Ghidra forwards STORE→LOAD IN-POOL via RuleLoadVarnode/RuleStoreVarnode
  (spacebase-placeholder model — the reason both rules sit BLOCKED in coverage). Consequence: a
  spilled value is fragmented from its live register, faithful per-def rules (SubRight/SubNormal)
  fire per-use-site minting single-use uniques (inlined), and the oracle's shared explicit var
  (`fVar1 = (float4)((uint8)param_1>>0x20)`, impliedfield) never forms. Evidence: Ghidra fires
  loadvarnode+storevarnode 1x + subright 1x@shared-def; mosura 0x/0x + 2x per-use. Fix = port the
  spacebase-placeholder model + both rules, cancel the overlapping stackvars behavior (task #7);
  explicitness heuristic + infertypes are already faithful, so one-varnode restoration likely
  suffices — re-measure before adding P5 merge.

FIX DIRECTION (policy-mandated, [[port-all-faithful-rules]] / CLAUDE.md no-adaptation-grandfathered): cancel the print-time/structuring adaptation, let the faithful IR rule normalize, then repair the downstream structuring/printer that depended on the adaptation. This couples into P7 structuring (#5) and P8 printc (#6) — it is the natural **Phase 1c** entry, and it is a gated corpus-MOVER (report delta + cause, wait for go). Instrument-first: dump oracle vs mosura IR to NAME each fix before writing.

**Why:** these are exactly the "faithful port dips the corpus → some OTHER non-Ghidra code is wrong → fix THAT" cases the mission is built on; the non-Ghidra code here lives in printc/structuring, not the rule. **How to apply:** when a tail rule lands as a regressing mover, check whether mosura already does that normalization non-faithfully downstream; if so, HELD-inert the faithful rule and queue the adaptation-cancel, don't revert the port.
