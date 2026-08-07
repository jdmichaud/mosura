---
name: war2-function-set-ground-truth
description: "WAR2's function-set ground truth is the expert tracker (2120), NOT Ghidra's cold run (1944) — mosura's real gap is 820"
metadata: 
  node_type: memory
  type: project
  originSessionId: df001909-493d-4f50-92ac-53ef8ca6337d
  modified: 2026-08-05T09:19:02.112Z
---

**Ground truth for "how many functions does WAR2 have" is
`/home/jd/projects/warcraft2-re/analysis/decomp-tracker.csv` (2120), NOT Ghidra's cold
`analyzeHeadless` whole-image run (1944).** Measured 2026-08-05 at rebased `analysis-port`:

| | count |
| --- | --- |
| tracker (expert-curated, each row has a source file + status) | **2120** |
| Ghidra cold whole-image | 1944 |
| in both | 1886 |
| **tracker-only (Ghidra MISSES)** | **234** — 153 `source-done`, 43 `matched-fixups`, 27 `matched` = real |
| Ghidra-only | 58 |

**Neither set is a subset of the other**; union ≈ 2178. Ghidra's cold auto-analysis is itself ~11%
short of the real function set.

**mosura @ rebased HEAD: 1303.** vs tracker → ∩1300, **MISSING 820**, mosura-only 3. vs Ghidra →
∩1303, missing 641, mosura-only 0. So **the real gap is 820 (61.5% recovered), not the 641** that
`war2-survey/analysis-gap/REPORT.md` §1 headlines — that report used Ghidra as truth and
understated the gap ~28%. I appended a §6 CORRECTION to that REPORT. The 3 mosura-only entries are
NOT false positives (they sit inside Ghidra's 58 — real, just untracked).

**Why this matters beyond the number:** the report's 3-mechanism seed taxonomy (tail call /
computed call / direct call, ~10 seeds) was derived against the 641, so it is **structurally blind
to the ~179 extra tracker-only misses** — Ghidra misses those too, so no Ghidra-vs-mosura diff can
see them. Re-derive the seed classification against the TRACKER after each fix. This is the same
trap as [[absolute-vs-differential-wrongcode]]: a differential scan cannot see a defect present on
both sides. Also an instance of [[goal-is-the-binary-not-ghidra]] — Ghidra-faithfulness is the
METHOD, the BINARY is the target; for the function-set question the expert tracker outranks Ghidra.

Also note mosura's 1303 was **unchanged** across 154 master commits — function recovery is inert to
decompiler-lane work.

MVE home for fixes: extend `oracle/ground-truth/` with **watcom-x86-32** variants (Open Watcom
`wcc386 -bt=linux`, WAR2's own toolchain). `ground_truth_parity.rs` already gates exactly the right
property (**0 spurious + full recall**), and truth is compiler-derived via nm+objdump, not Ghidra.
`tailcall`/`fnptr`/`dispatch` exist only for gcc targets — that missing watcom column is why the
bug never surfaced in-corpus. See [[mve-first-then-solve-the-mve]],
[[war2-issues-become-source-tests]].

## ROOT CAUSE FOUND (2026-08-05) — a DISASSEMBLY-COVERAGE gap, not function-creation

Measured mosura's OWN reference set (20,324 refs) on WAR2, not its `[entry,next_entry)` extents
(extents are an upper bound and mislead — that is what made REPORT §2/§3 misdiagnose):

- Of 815 missing functions, mosura holds a reference to only **32**; **ZERO** `UnconditionalCall`
  refs point at any missing function.
- For every Ghidra `UNCONDITIONAL_CALL` into a missing function, **1548/1549 call sites are not in
  mosura's reference set** — it never decoded the calling instruction.
- **mosura never disassembles 24.7% of the code object** (109,338 B in 23 regions >2KB; the biggest,
  `00039bd4..0003ca39`, contains 28 tracker functions). mosura's first fn is `1011e`; the tracker's
  first three (`10010/10063/100b9`) are never reached.
- Flow-following is HEALTHY within reach: at each gap mosura decodes its preceding function
  completely (e.g. `00039b6c`, Ghidra size 112 → ends `39bdc`, mosura's last ref `39bcd`) and simply
  never starts the next one.

**The 783 are a subgraph disconnected from mosura's seeds** — its members call each other, and the
only edges in from outside are **DATA** (region `39bd4` entered by DATA×11 + CALL×8; `00010010` is
DATA-referenced from `00083436`/`00083404`, i.e. from the DATA OBJECT above code-end `0x7C4A0`).

⇒ **Missing mechanism = function pointers in data.** mosura's analyzer set is
`{demangler, eh_frame, external_jump, noreturn, shared_return, switch}` — it has NO address-table /
data-operand-reference analysis. Port targets: Ghidra `DataOperandReferenceAnalyzer` +
`OperandReferenceAnalyzer` (+ address-table creation) in
`Features/Base/.../app/plugin/core/analysis/`. This is why fixing 5 seeds recovered 5 functions and
not the 590 REPORT §2 predicted — **the cascade model is false**; no seed-fixing reaches a
disconnected component.

### Landed so far
`5d1a550` tailjmp MVE (watcom-x86-32, backward+forward arms) + `8a13977` port
`SharedReturnAnalysisCmd.applyTo` verbatim, retiring an INVENTED veto in
`could_have_fall_thru_to` ("a location inside a function body needs a fall-through predecessor" —
no Ghidra counterpart; a tail-call dest is always inside the jumper's body, so it vetoed every
shared-return dest). MVE **verified fails at pre-fix commit, passes at HEAD**. 1303→1308, 0 false
positives. Also corrected the taxonomy: the 3 "direct call" seeds are `jmp`s — Ghidra reports
`UNCONDITIONAL_CALL` only AFTER the CALL_RETURN override that rule applies.

## RESOLVED: how the 2120 were recovered, and the port that closed 42% of the gap

**The procedure, documented in `warcraft2-re/analysis/bootstrap.md` §3-4** (user pointed me there;
I had wrongly inferred a Ghidra "ceiling"): SAME Ghidra, **no analyzer-option changes anywhere**.
The only difference is WHICH IMAGE: `tools/ghidra/relocate_war2_elf.py` applies the LE fixup table
first (**~17,517 relocations, 3,178 into code**), then plain `load_program` + `run_analysis` →
**"~2145 functions (vs ~1828 on the un-relocated WAR2.elf — the difference is the recovered
indirect graph)"**. The gap report's 1944 sits between the two ⇒ its ELF was built differently;
**1944 is an unreliable baseline**. Ghidra CAN reach ~2145, so there is no faithful-port ceiling.

**mosura is in the identical position to Ghidra**: `le.rs::apply_le_fixups` patches bytes and emits
NO references, exactly like `relocate_war2_elf.py` ("relocating is simply writing target_base+
target_offset into each slot"). Neither tool gets relocation *records*. So Ghidra recovers those
functions purely via analyzers discovering pointers in relocated data. ⚠️ Tempting non-faithful
shortcut to REFUSE: mosura's LE loader *could* emit references straight from the fixup table (it
knows which slots are pointers, Ghidra doesn't) — Ghidra does not do this; porting the analyzer is
the faithful path and generalises beyond LE.

**LANDED `dcd3c9f`(MVE)+`93ca489`(port): AddressTableAnalyzer + AddressTable +
PseudoDisassembler.isValidCode/checkPseudoBody.** Ghidra named the analyzer itself via its
bookmark (`Address Table : Address table[4] created`) — instrument, don't guess.
**1308 → 1653 functions; missing 815 → 475; 0 lost; 1 false positive.** Verified by me
independently (numbers, suite 591/0, clippy 0).
- **No Ghidra analyzer creates a function at a data-pointer target** — `AddressTableAnalyzer:281`
  "For Now, Never make functions from address tables", `OperandReferenceAnalyzer.createFunctions`
  :614 and `DataOperandReferenceAnalyzer` :39 are empty. They DISASSEMBLE; functions then come from
  direct calls inside the new code. So `DataOperandReferenceAnalyzer`/`OperandReferenceAnalyzer`
  were the WRONG port targets (also PE-gated off for ELF).
- The 1 FP `0x000388d4` is a coverage-convergence artifact (offcut-collision check sees different
  input because the tools disagree whether `0x60000` is an instruction), not over-creation.
- **Pre-existing loader mis-port fixed en route:** `ElfProgramBuilder.findLoadAddress` (:3043) was
  never ported — mosura assumed file offset 0 loads at image base (true for gcc, false for Open
  Watcom `wlink` whose first PT_LOAD starts at 0x100), laying `Elf32_Ehdr` OVER the first function
  and making `checkPseudoBody` veto everything. **Every watcom-x86-32 fixture carried this.**
- Remaining 475 is no longer one mechanism: mosura finds 129 of Ghidra's 148 tables (19-table delta
  = next step), and Ghidra itself lacks 234 tracker functions.

## ⚠️⚠️ EVERYTHING ABOVE KEYED ON "1944" IS WRONG — it was a FORCED-CSPEC ARTIFACT (2026-08-05)

`analyzeHeadless -processor "x86:LE:32:default"` (the gap report's recipe) **bypasses the ELF
opinion and lands cspec `windows` on an ELF — costing 201 functions.** Verified by me, both runs,
byte-identical image, same 30 s analysis:

| invocation | cspec | funcs |
| --- | --- | --- |
| `-processor "x86:LE:32:default"` | **windows** | **1944** |
| no `-processor` (opinion decides; = the MCP path) | **gcc** | **2145** |

**Ghidra's true cold number on WAR2_reloc.elf is 2145.** `bootstrap.md`'s ~2145 and
`ensure_loaded.py`'s ~2147 were correct and were always cold figures. There is NO "1944 +
~200 agent-created" story — I constructed that reconciliation and it is false. Four repeated 1944
runs were four repetitions of the WRONG QUESTION → the textbook
[[oracle-same-question-not-just-same-tool]] trap. **When an oracle number disagrees with a
documented one, check the INVOCATION before inventing a story that explains the gap away.**

**Corrected numbers (mosura @ `06ef407` = 1653):** ∩Ghidra 1652 · **Ghidra-only gap 493** · FP 1 ·
Ghidra∩tracker **2025** · **tracker-only only 95** (not 234) · ghidra-only 120 ·
**union = 2240 = the real target**. So Ghidra is short by 95, NOT "~11% short of the real function
set" — that conclusion is void, as is the 815-missing denominator (real: 2240−1653 ≈ 587 vs union).
The §7 MECHANISM findings survive (measured from mosura's own reference set, not the Ghidra diff).
