# The struct-copy arm (`struct-copy={ghidra,assign}`, W6)

**What Watcom did.** A struct assignment at or below its unroll threshold compiles to an ESI/EDI
setup and a run of k plain `MOVSD` (opcode `A5`, one byte each, no `REP`, no ECX) — `struct
p16 tmp = *(struct p16 *)src` is `LEA EDI,[EBP-0x34]; LEA ESI,[..]; A5 A5 A5 A5`. `memcpy(d, s, 4k)`
is NOT the same source: with the intrinsic it always yields the `REP MOVSD` + `REP MOVSB` pair
(docs/rep-string-intrinsic-arm.md). Ghidra prints the run as k dword copies, and k dword copies
recompile as k `MOV` pairs.

**Population (fable-b's byte census on the w5c tree, compiler-built game code).** No lone `REP
MOVSD` exists at all (the only two are in the hand-written blitter 0x10010); the family is the
unrolled run: 12 runs in 8 functions — 0x38158 ×3 (k=4, an element swap through a stack temp),
0x51298 ×2 (asm-kind, no verdict), 0x20258 ×2 (k=3, globals 0xa7fe0/0xa7fec → 0x8faf0/0x8fb80),
0x2913c (k=3, from 0xa7fe0), 0x35d44 (k=3, between two entries of the table at 0x84704), 0x40470
(k=2, from 0x87ab0 into `[EAX+0xc]`), 0x439e8 and 0x44a04 (k=2, `[reg + idx*8 + 6]` into a pointer).
The srcform5r probe (`struct p16 { uint4 a, b, c, d; }`, three assignments through
`(struct p16 *)` casts, `struct p16 sTemp;` for the swap) reproduced the MOVSD runs byte-exact at
0x38158's three sites.

**The arm.**
- Witness (`buildconfig::movsd_runs_from_evidence`): runs of consecutive one-byte `A5`
  instructions in the original, start pc → k (k ≥ 2), fed through `RecoveredChoices::movsd_runs`.
- Types: `struct p8 / p12 / p16` (k dwords) in the survey prelude.
- Load/store runs (`movsd_run_stmt`): the k dword copies sit at pcs `p..p+k` — a `STORE` fed by a
  `LOAD` at the SAME pc, or the explicit assignment the load/store rules made of a global; the
  first copy's destination and source addresses become `*(struct pN *)dst = *(struct pN *)src`
  (an address's own pointer cast is dropped inside the struct cast); the run's other copies are
  skipped. The hook fires once, at the run's first member. A copy whose load belongs to another
  pc declines: copy-propagation had carried 0x38158's temp loads into its third run, and fusing
  that would re-read `a[i9]` after the second run overwrote it.
- Global-to-global runs (`movsd_global_run`): heritage re-homes those copies at the block's exit
  (0x20258's `xRam0008faf0 = xRam000a7fe0;` prints at the `JMP`'s pc, writing uniques merged into
  the globals' HighVariables), so the witness matches the SHAPE — k consecutive printable copies
  `ram[A+4i] = ram[B+4i]` (A ≠ B, addresses through the High's ram member) with k a witnessed run
  length.
- Fixtures/tests: `x86_40470_struct_copy.xml` (k=2 into a pointer), `x86_20258_struct_copy_globals.xml`
  (two k=3 global runs) — `tests/struct_copy.rs`.

**Follow-up.** 0x38158's swap: the temp runs (loads into four scalar temps, stores back from them)
need the aggregate `struct p16 sTemp;` — the four Highs defined by run 1 and consumed by run 3 as
one struct local (`sTemp = *(struct p16 *)a; ... *(struct p16 *)b = sTemp;`). The middle run
renders today.

**Landed 2026-08-27 — round `w6a` vs `w5c`:** WGSS 0.5568 → 0.5576 (+0.0008; 9 movers, all up:
0x40470 +0.647, 0x60130 +0.272, 0x439e8 +0.225, 0x5c990 +0.219, 0x20258 +0.217, 0x35d44 +0.093,
0x38158 +0.051, 0x6d990 +0.032, 0x2913c +0.032), EXACT 856 → 857 (0x40470), SAME_SHAPE +1
(0x439e8), COMPILE_FAIL at the baseline 1, no verdict regression; gated suite 974 pass / 0 fail.
