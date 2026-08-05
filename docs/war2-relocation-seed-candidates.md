# WAR2: functions found by relocation-seeding that neither oracle has

51 addresses that mosura's `RelocationSeedAnalyzer` (beyond-Ghidra; see
`crates/mosura/src/analysis/analyzers/relocation_seed.rs`) turns into functions on
`WAR2.EXE` via `analyze_le_file`, and that appear in **neither**:

- Ghidra's cold auto-analysis of the relocated ELF wrapper (2145 functions — note: run
  WITHOUT `-processor`, which would force compiler spec `windows` and cost 201 functions), nor
- the expert tracker `warcraft2-re/analysis/decomp-tracker.csv` (2120 functions).

**The three entries that land inside a known function body are documented in the analyzer's
module doc and are NOT part of this list** — they were investigated and turn out to be
secondary entry points reached by direct calls (6 and 9 call sites for two of them), not
artifacts of this pass.

**They are not known to be wrong.** Every one sits in a gap *between* tracker functions, never
inside one (the 3 that do land inside a known body are listed separately, in the analyzer's
module doc). Gap sizes between the surrounding tracker functions: min 6 B, median 422 B, max
4154 B. Each was reached from a slot in the linker's own fixup table — an exact record of a
stored pointer, not a heuristic — and passed `PseudoDisassembler::is_valid_subroutine`.

**This is an adjudication request, not a claim.** If they are real, mosura has found functions
both Ghidra and the tracker missed, which under the project's pragmatism directive is a result
worth having. If they are not, they are the visible part of the over-decoding defect recorded
in the same module doc.

```
00010aac 00010ac2 00010afa 00010b84 00010f3c 0001768c 00017850 00022638
0002ae44 00030a44 00030b00 000388d4 00038cf4 000392bc 000393fc 00039430
0003944c 00039468 000394a0 000394bc 00039554 00039588 000395f0 00039638
00039680 000396b4 000396e8 0003b4e0 0003bfb4 0003cab4 0003f30c 00042e18
0004a8b0 0004b3c4 0004b750 0004b7f4 0005360a 000536f6 0006a8a0 0006a970
0006ed10 0006eec5 0006eeee 0006ef5a 000714c5 00078a47 00078aa1 00078af8
00078b6a 00078b75 00078bf2
```

Note `000388d4`: this is the address that was mosura's lone false positive before the
relocation filter landed (`019afc5`), which killed the bogus table at `0x86af0` that produced
it. It returns here by a different route — a genuine fixup slot — so it is worth adjudicating
first: it is the one candidate we already know two mechanisms disagree about.
