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
- **V2 `memcmp` (built 2026-08-26, round-trip POC first):** hand-editing `0x11a50`'s TU to
  `iVar1 = memcmp(param_1, (uint1 *)0x8efc4, iVar2)` under `#pragma intrinsic(memcmp)` took the
  function MISMATCH → **EXACT** (0 divergent rows; was 32) — Watcom's template `XOR EAX,EAX; REPE
  CMPSB; JZ L; SBB EAX,EAX; SBB EAX,-1; L:` (a −1/0/1 result) reproduced byte-for-byte. The lifted
  shape (fixture `x86_repe_cmpsb.xml`): at the CMPS pc, `LOAD a`/`LOAD b`, `INT_LESS(a,b)` = CF and
  `INT_EQUAL(a,b)` = ZF (the loop condition); after the loop, EXIT phis of both flags, a `CBRANCH`
  on ZF (the `if (!bVar3)`), and the result chain `r1 = 1 - zext(CF) - zext(CF != 0)` merged with a
  `0` in the result phi. Recognizer: find that structure, check the flags feed only it and the
  pointers are dead after the loop, then render `r = memcmp(a, b, n);` at the loop node and skip
  every node whose live ops all sit at the if-node's pcs (`rep_skip`); suppress the chain ops and
  the pre-loop `r = 0; cf = 0; zf = 1;` phi-entry COPYs. Witness: `F3 A6` (REPE CMPSB; A7 = CMPSD).
  Prelude: `int memcmp(const void *, const void *, unsigned)` + the pragma. Ceiling (fable-b, from
  the bytes): 12 REPZ CMPSB sites in game code + 8 in the Miles region. **Measured (stringops3 vs
  stringops2): 12 game `memcmp` calls recognized in 11 functions (0x11a50 0x137b8 0x13ad8 0x1f734
  0x1f7b8 0x2be6c 0x324d0 0x32a3c 0x32d64 0x3318c 0x332c4) + 10 library; WGSS 0.5364 → 0.5424
  (+0.00607, +743 insn-sim); EXACT 834 → 837 (0x11a50, 0x32a3c, 0x32d64 → EXACT; 0x32d64 is the #3
  game-loss function, 315 insns, 0.279 → 1.000); 19 moved, 19 up, 0 down, no sim-downs.**
  V3 candidate (fable-b's round-trip POC at 0x16118): `strlen` via `REPNE SCASB` — Watcom re-emits
  `SUB ECX,ECX; DEC ECX; XOR EAX,EAX; REPNE SCASB; NOT ECX; DEC ECX` from `strlen()` under the pragma.
- **V3 `strlen` (LANDED 2026-08-27; fable-b's round-trip POC at 0x16118 reproduced the
  template `SUB ECX,ECX; DEC ECX; XOR EAX,EAX; REPNE SCASB; NOT ECX; DEC ECX` from `strlen()` under
  `#pragma intrinsic(strlen)`).** Lifted shape (fixture `x86_repne_scasb.xml`, all loop ops at the
  SCAS pc): `cnt = 0xffffffff; do { if (cnt == 0) break; cnt = cnt - 1; c = *p; p = p + 1; }
  while (c != '\0');` then the template's `NOT; DEC` as `~cnt - 1` on the exit count (a
  MULTIEQUAL of the count phi and its decrement). Corpus census on the w1e tree: **24 loops, 22 in
  game code across 19 functions** (0x16118 0x16598 0x16668 0x2bb10 0x2ddf8 0x49720 0x49ad8 0x49d30
  0x49df8 0x4a330 0x4b338 0x50604 0x507d4 0x5b91c 0x5d0c8 0x5d100 0x5d138 0x5d394 0x5d7c8) = the
  whole game ceiling fable-b counted from the bytes. What the sites do with the exit count: `~cnt -
  1` (= the length: assignments, call arguments, compares, a `(char)` store); `~cnt` alone (=
  length + 1 — Ghidra folded the user's `+ 1` into the template's `- 1`: `malloc(~cnt)` at
  0x16598/0x16668, `if (~cnt != 1)` at 0x2ddf8/0x5d100/0x5d394, `cnt = ~cnt` at 0x4a330); `~cnt -
  2` (length − 1, 0x6d870); and two sites whose count is dead (0x2bb10, 0x49ad8 — the scanned
  pointer is what they use; not a source-level `strlen`, left as loops). Design (as landed, each
  rule named by a probe): the exit count's only live reader must be an `INT_NEGATE`; the value the
  arm names is always the LENGTH (what `NOT; DEC` leaves in ECX) — the `INT_SUB(neg, 1)` output
  when that chain exists, else the negate's own output — assigned at the LOOP's position
  (`r = strlen(s);`, where the original's template sits: fable-b's round-trip POC at 0x16118 was
  position-exact there) when the result is explicit, read more than once, or read by nothing the
  printer shows (0x2bb10: the length is a hidden third call argument the recovered prototype
  lacks — the missing-args backlog; dropping the loop there lost the template rows), and inlined
  `strlen(s)` at its single implied use otherwise. Every reader of the bare negate is `len + 1`
  with its constant re-adjusted (`strlen_fold`: `~cnt != 1` → `len != 0`, `~cnt - 2` → `len - 1`),
  undoing the fold Ghidra applied to the template's `DEC` — the probe rows at 0x5d100 showed the
  literal `strlen(p) + 1 != 1` compiling to `INC ECX; CMP ECX,1` against the original's `TEST
  ECX,ECX`, and `p + strlen(p) + 1 - 2` to `[ECX-2]` against `[ECX+EDI-1]`. The argument prints
  with `(char *)` when its type is not a char pointer (the entry resolver crosses the phi input's
  CAST; Watcom's intrinsic type-checks the parameter — `E1071`, 6 COMPILE_FAILs in the first probe;
  Ghidra's `castInput` for the `const char *` parameter). Value guard: the chain sits in the loop's
  exit block with no CALL/STORE before it and nothing between reading the result's variable
  (phis excepted — the exit MULTIEQUAL's inputs share the count's variable when the negate assigns
  into the count itself, 0x4a330). Loop node and the `cnt = -1; p = s;` entry copies suppressed.
  Witness: `F2 AE` (REPNE SCASB; `AF` = SCASD). Prelude: `unsigned strlen(const char *)` + the
  pragma.
  **Measured (round w2b vs w8, 2026-08-27): WGSS 0.5433 -> 0.5450 (+216.0 insn-sim, +0.00176); 840 EXACT held, 0 lost; SAME_SHAPE 76 -> 78 (0x5d0c8, 0x5d100 MISMATCH -> SAME_SHAPE); 21 TUs moved, 19 up / 2 down (0x2bb10 -0.018: the missing-args site; 0x614fc -0.012: the W8 fix-up's correct goto replacing wrong code); no new COMPILE_FAIL; game memcpy/memset/memcmp unchanged (78/0/20), 20 strlen calls in 17 functions (10 with the cast), the 2 pointer-product loops kept; largest movers 0x4b338 0.225 -> 0.921, 0x5d7c8 0.595 -> 0.905, 0x5d0c8 0.276 -> 0.852, 0x5d100 0.296 -> 0.852, 0x49720 0.394 -> 0.719.** The 0x5d100 witness: `TEST ECX,ECX` now
  matches (the row left the divergences); its residual is Watcom folding `p + (len - 1)` into
  `ADD ECX,[EDX+0x14]; MOV byte [ECX-1]` where the original keeps `p` in EDI (`MOV EDI,[EDX+0x14];
  MOV byte [ECX+EDI-1]`) — an addressing/allocation choice, not the arm's. First probe (w2p) had
  6 COMPILE_FAILs (the missing `(char *)`, E1071) and an over-inlined multi-use result; both fixed
  by a hand-patched POC on the same tree before this round.
- Follow-up seen while building V3 (w8 tree): 61 of 140 `memcpy` lines sit beside a stray
  `x = n >> 2;` / `x = n & 3;` statement — the runtime-length pair's split counts are `INT_RIGHT`/
  `INT_AND` ops assigned to explicit variables, and the phi-entry suppression covers only the COPY
  links. 29 TUs (14 game: 11 MISMATCH, 3 EXACT — the EXACT ones show Watcom dead-stores them when
  the temp is otherwise unused). Suppressing an op whose only live uses are the suppressed entry
  chain would remove them; measure before assuming it moves bytes.
- Later: `memset` pairs need only the same recognizer (no game sites use REP STOS; libraries do).
