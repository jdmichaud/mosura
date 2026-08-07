---
name: war2-address-table-port
description: "2026-08-05 — porting AddressTableAnalyzer/AddressTable/PseudoDisassembler.isValidCode took WAR2 from 1308 to 1653 functions (missing 815 -> 475), with 1 false positive vs Ghidra."
metadata: 
  node_type: memory
  type: project
  originSessionId: df001909-493d-4f50-92ac-53ef8ca6337d
  modified: 2026-08-05T13:56:50.505Z
---

Landed on `analysis-port` (mosura-analysis worktree): `dcd3c9f` the MVE, `93ca489` the port.

**What it closed.** `war2-survey/analysis-gap/REPORT.md` §7's second gap: code reachable only
through a function pointer stored in data was never disassembled. Ported
`AddressTableAnalyzer` + `AddressTable` (`plugin/core/disassembler/`) + `PseudoDisassembler`
`checkValidSubroutine`/`checkPseudoBody`/`isValidCode` + `RepeatInstructionByteTracker`
(`Framework/SoftwareModeling/.../app/util/`).

WAR2 via `analyze_le_file`: **1308 -> 1653 functions**, missing vs the 2120-function tracker
**815 -> 475**, **0 lost**. Of 350 newly recovered, **349 are in Ghidra's set and 345 in the
tracker**. mosura finds 129 address tables / 1456 pointer slots; Ghidra 148 / 1609.

**The one false positive (`0x000388d4`) is NOT a port defect** — it is an upstream disassembly
disagreement. `AddressTable.getEntry` rejects a run the moment `checkForCollisionAtTarget`
(:1339) finds an entry pointing *offcut* into an existing instruction. At `0x86af0` the run's
first value is `0x60003`; Ghidra has an instruction at `0x60000` len 7, so `0x60003` is offcut
and the table dies. mosura decoded an instruction *starting* at `0x60003` (both tools follow the
same `UNCONDITIONAL_JUMP` from `0x5fff0`), so no collision, table accepted, and a call inside the
newly decoded region created a function neither Ghidra nor the tracker has. Same check, different
input. It converges away as coverage converges.

**Blocker found on the way, worth remembering:** mosura's ELF loader had not ported
`ElfProgramBuilder.findLoadAddress` (:3043) and assumed file offset 0 loads at the image base.
True for gcc (first `PT_LOAD` has `p_offset == 0`), false for an Open Watcom `wlink` image whose
first `PT_LOAD` starts at file offset 0x100 — mosura was laying a 52-byte `Elf32_Ehdr` straight
over the first function, and `checkPseudoBody`'s "no defined data in the body" rule then vetoed
every candidate. Fixed in the same commit.

**⚠️ THE ORACLE WAS ASKED THE WRONG QUESTION — Ghidra's cold number is 2145, not 1944.**
`analyzeHeadless ... -processor "x86:LE:32:default"` (the gap report's command) BYPASSES the ELF
opinion and lands compiler spec **`windows`** on an ELF → **1944** functions. Dropping the flag and
letting the loader auto-detect gives cspec **`gcc`** → **2145**. Same language
(`x86:LE:32:default`), same byte-identical relocated image, same 30 s cold run; only the compiler
spec differs, and it is worth **201 functions**. bootstrap.md's "~2145" was right all along and IS
a cold figure — I briefly concluded otherwise from four consistent 1944 runs, which were four runs
of the wrong question. Textbook [[oracle-same-question-not-just-same-tool]].

Consequences: everything keyed on 1944 is an artifact. Against the CORRECT oracle —
Ghidra 2145, mosura 1653, **1 false positive**, 493 Ghidra-only remaining (not 292);
Ghidra ∩ tracker = 2025 so Ghidra misses only **95** tracker functions (not 234), and
union(Ghidra, tracker) = 2240. `war2-survey/analysis-gap/REPORT.md` §1/§6's baseline and its
"Ghidra's cold auto-analysis is ~11% short of the real function set" conclusion are void.
**Never pass `-processor` to analyzeHeadless for WAR2_reloc.elf.**

Table recall vs Ghidra on the relocated image: mosura **129 tables / 1456 pointer slots**, Ghidra
**148 / 1609**, 109 table tops identical — many of the rest are the SAME table trimmed
differently at the head (Ghidra `00014f54` vs mosura `00014f58`), so real agreement is higher
than the raw counts.

Rules that came out of this: [[ghidra-never-makes-functions-from-data-pointers]].
Gate: `ground_truth_parity::data_pointer_function_discovery`, MVE
`oracle/ground-truth/src/datafnptr.c`.
