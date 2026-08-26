# The `string-ops = intrinsic` emitter arm — render a lifted `REP MOVS` loop as `memcpy`

## Goal & layer

`REP MOVSD`/`REP MOVSB` lifts to an internal p-code loop; mosura prints it as a counted `for` loop
(now with a clean `+1` stride after the tracked_set port). Watcom recompiles that loop *as a loop*,
so it never byte-matches the original `REP MOVS`. This arm recognizes the lifted rep-string loop and
renders `memcpy(dst, src, n)` (`memset` for `REP STOS`) instead, which Watcom under `-oi`/`-onatx`
**re-inlines to `REP MOVS`** — recovering the bytes. This is the single largest named WGSS lever
(`docs/wc2src-wgss-lowsim.md`: 137 TUs, 8,859 loss ≈ 15%).

It is an **emitter arm** (render layer), not a decompiler change: the decompile runs once, the arm
is a form choice over the finished IR (like `array-index`/`narrow-tests`). No second pass. Faithful
per the emit.rs contract: both arms are value-identical renderings of the same IR, and `intrinsic`
is **byte-witnessed** on the original instruction actually being `REP MOVS`.

## Recognition (verified from the fixture IR)

Every p-code op of a lifted rep-string shares one `seqnum.pc` = the `REP MOVS` instruction address.
The loop body (dumpc `--raw` of `oracle/fixtures/x86_repmovsd.xml`, all at pc `0x600e`):

```
CBRANCH …                       ; guard exit
r_cnt = INT_ADD r_cnt, #-1      ; ECX--
u = LOAD  ram, r_src            ; *ESI      (size 4 = movsd, 1 = movsb)
        STORE ram, r_dst, u     ; *EDI = …
r_dst = PTRADD r_dst, #1, #sz   ; EDI += sz  (sz = 4 movsd / 1 movsb)
r_src = PTRADD r_src, #1, #sz   ; ESI += sz
INT_NOTEQUAL r_cnt, #0          ; loop while ECX != 0
… MULTIEQUAL phis for r_cnt / r_src / r_dst (loop-entry = initial ECX/ESI/EDI)
```

Recognizer (a pre-pass in `print_c_inner`, mirroring N3 `array-index` at printc.rs:5029): find the
`STORE`/`PTRADD` cluster all sharing one pc with this shape; record a candidate keyed on that pc,
carrying `(dst, src, count varnodes, element size sz, is_set)`. `dst`/`src`/`count` are the
loop-entry values of the `MULTIEQUAL` phis (initial EDI/ESI/ECX).

## Witness (byte-exact)

`buildconfig::string_ops_from_evidence(cands, &insns)`: for each candidate pc, find the `NormInsn`
at that address and confirm a repeated string instruction by bytes — `bytes[0] ∈ {0xF2, 0xF3}`
(Watcom 10.0a emits the **REPNE `F2`** prefix; F2/F3 are equivalent for MOVS/STOS) and
`bytes[1] ∈ {0xA4 movsb, 0xA5 movsd, 0xAA stosb, 0xAB stosd}`. The same `*_from_evidence` shape as
the other witnessed arms; the original disassembly is already produced in war2_survey (`normalize`).

## Render

At the loop's structured node (`emit_structured_body` `WhileDo`/`DoWhile`, printc.rs:3167/3224), when
the loop's pc is in the recovered `string_op_sites`, emit a statement `memcpy(dst, src, size);` (or
`memset(dst, val, size);`) instead of the loop header+body, and suppress the loop's ops. Render the
operands via `render_var`. `memcpy`/`memset` are declared in the prelude (like `__int3` for `swi=int3`,
emit.rs:236/printc.rs:4998) so the recompile links them and Watcom's intrinsic re-inlines them.

### Sizing

`REP MOVSD` copies `ECX` dwords; `memcpy` takes bytes. Watcom 10.0a's intrinsic always splits a
copy into a dword loop (`n>>2`) and a byte loop (`n&3`) — see the POC below — so the recognized
unit is the pair and the size is: `c1*4 + c2` when both counts are constants (a struct copy /
`sizeof`); the pre-`>>2`/`&3` varnode `n` when both derive from one runtime length; else the
value-identical `count1 * 4 + count2`. A lone loop sizes as `count * elem`.

## Round-trip POC (2026-08-26) — the premise, verified on a GAME site first

Lesson first: the arm was initially built and measured (round `stringops`: +0.0002 WGSS, 0 EXACT)
**before** the compiler round-trip had been probed, and the round measured it only on foreign
(≥0x5f000, other-toolchain) sites — where Watcom 10.0a's intrinsic cannot match by construction.
The decisive probe took minutes: hand-edit `sfile_write_game` (0x33efc)'s TU, replace one
MOVSD+MOVSB pair with `memcpy(pTemp, gfpUnitMap, 0x10000)` under `#pragma intrinsic(memcpy)`,
`recompile_check --only 0x33efc --verbose`. **For any byte-exact arm, run this probe before
building anything.**

What the bytes taught (all needed, none assumed):
1. **A bare prototype compiles `memcpy` to a `CALL`.** `-onatx` already includes `-oi` (x =
   obmiler), but Watcom inlines only under `#pragma intrinsic(memcpy,memset)` (string.h's pragma).
   The prelude now carries it. No flag change.
2. **The template is a PAIR, always.** Watcom 10.0a expands `memcpy` as `MOV EAX,ECX; SHR ECX,2;
   REP MOVSD; MOV CL,AL; AND CL,3; REP MOVSB` inside `PUSH EDI…POP EDI`, **even for a constant
   length** (0x10000 → it still emits `n&3`), and struct assignment uses the identical template. So
   the recognizer's unit is the dword-loop + byte-loop pair sharing the advanced pointers; a
   dead-pointer gate on the first loop rejects every game site.
3. **The prefix is `F2` (REPNE), not `F3`.** Every game rep site is `f2 a5`/`f2 a4`; the recompile
   emits `f2` too (byte-identical). A witness keyed on `0xF3` rejects every game site.
4. **The decrement is `INT_SUB(self,1)` once the count is typed unsigned** (`INT_ADD(self,-1)` when
   signed); the count recognizer accepts both.
5. **The length constant is hoisted above a preceding CALL** (`MOV ECX,0x10000` before the malloc:
   ECX is callee-preserved under `__watcall`) — the recompile reproduces that too, once the dead
   phi-entry assignments (`pxVar6 = pTemp; iVar4 = 0x4000;`) are suppressed so the C is exactly the
   source's `memcpy(dst, src, n)`.
6. Harness artifact: a rep-string op's `sem` embeds its internal self-branch address, so a
   layout-shifted but byte-identical REP row never reads `Equal` in `align.rs` (`[operand-form]`).
   TODO: exclude the self-branch target from a rep-string op's sem key.

Probe result at 0x33efc: the whole template reproduced as clean rows; 303 → 212 divergent rows
from ONE of its 8 memcpys.

**Probe-scale measurement (the 48 game rep-string functions = the whole game ceiling: 63 MOVSD +
61 MOVSB, 0 STOS):** 62/62 pairs recognized in 48/48 TUs, 0 residual loops; recompile: 46 up / 0
down, +987 insn-sim; 9 verdict flips, all upward (MISMATCH→EXACT 0x11b44 0x225e0 0x2a0ec 0x2b184
0x34540; →SAME_SHAPE 0x31e2c 0x32168 0x3242c 0x49450). Zero regressions.

## Plan
- **V1 (built):** axis `string-ops={loop,intrinsic}`; pair-aware recognizer (`RepLoop`/`RepMovs`,
  size = `c1*4+c2` | the pre-`>>2`/`&3` varnode | `count1*4+count2`); witness `F2|F3` MOVS/STOS;
  prelude pragma; dead phi-entry COPY suppression; fixtures `x86_repmovsd.xml` (single) and
  `x86_repmovs_pair.xml` (runtime-n pair); war2_survey selects `string-ops=intrinsic`.
- **Corpus round (stringops2 vs tracked, 2026-08-26): WGSS 0.5234 → 0.5364 (+0.01295, +1586
  insn-sim); EXACT 828 → 834; SAME_SHAPE 75 → 79; 10 verdict flips, all upward, 0 downward
  (→EXACT 0x11b44 0x225e0 0x2a0ec 0x2b184 0x34540 0x6f8f4; →SAME_SHAPE 0x31e2c 0x32168 0x3242c
  0x49450); 86 movers, 84 up / 2 down — the 2 downs (0x6f94c −0.003, 0x626c0 −0.002) are
  library-zone, verdict-unchanged, value-identical noise.** Full suite green.
- Later: `memset` pairs need only the same recognizer (no game sites use REP STOS; libraries do).
