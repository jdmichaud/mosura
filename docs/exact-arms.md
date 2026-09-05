# The EXACT push (2026-09-03) — witnessed emit choices from the near-miss census

## Where the functions were

The divergence census (`divergence-classes.md`) counts rows, and rows are dominated by big
functions. The EXACT count is won elsewhere: on the base (`c0ef3d3`, 876 EXACT) 179 non-exact
functions were within THREE root divergence rows of exact (a root row = anything but the
layout-shift and branch-target rows that follow from another divergence), and 411 within six.
Clustering those rows by normalized instruction shape gave a short list of rule-shaped families,
and each was settled the same way: a hand-edited probe TU compiled through the real Watcom 10.0a
(`recompile_check --only`) to find the C form that reproduces the bytes, then a byte WITNESS the
survey can read from the original, then the arm. Nothing here is a Ghidra port; every arm is a
target-informed emit choice in the survey's recovered rendering, off in the reference one.

| arm | witness | family (base) | fixture |
| --- | --- | --- | --- |
| narrow one-case `switch` (`sparse_switch.rs`, `try_emit_narrow_switch`) | `sparse_cmp_sites`: a 16-bit register compare (`MOV AX,[..] ; CMP AX,k` / `TEST AX,AX`) at the clause's branch | the message dispatchers, `if ((*p == 9) && (p[1] == 0))`: 89 functions | `x86_watcom_narrow_switch.xml` |
| `cmp-order` (`cmp_order.rs`) | the `CMP`'s operand order at the compare: the port's right operand named first = the source wrote the mirrored `b > a` | `SETG`/`SETL`, `JGE`/`JLE` swaps: 65 functions | `x86_watcom_cmp_order.xml` |
| narrow zero-extension cast (`printc.rs`, the promotion arm) | `narrow_zext_sites`: `XOR AH,AH` within four instructions of the extension's consumer | `(uint2)byte * 2` stored to a short: 128 functions carry the idiom | `x86_watcom_narrow_zext.xml` |
| `return-width`, the byte return (`narrow_return_from_evidence`, width) | every return site's last A-family write is `AL`/`AX`; a `CALL`-defined site is neutral; the returned variable retypes with the declaration | `XOR AL,AL` / `MOV AL,1` / `MOV AL,DL` returns | `x86_watcom_byte_return.xml` |
| stack store order (`stack_store_orders_from_evidence`) | the original's own `MOV [EBP + off],..` sequence over a run of pure frame-slot stores | a parameter stored into a buffer passed to a call, printed after the constants | `x86_watcom_stack_order.xml` |
| entry snapshot, widened (`snapshot.rs`) | unchanged (one narrow load at entry); the candidate set now admits any READ of the global, never a written global | `MOV AL,[g]` then `MOV DL,AL`: the 0x39554 family | (the arm's own fixture) |

Three more arms followed in the same method (rounds e8–e10):

| arm | witness | family | fixture |
| --- | --- | --- | --- |
| `mask-cast` (`mask_cast.rs`, at `ValueSite::CallArg`) | the original's `AND r,0xff\|0xffff` on the argument's register, the LAST write of that register before the call | a `WORD` argument Ghidra's `RuleAndMask` proved redundant and dropped: the `+ 0xbbb` message-id family, 23 near-miss functions | `x86_watcom_mask_arg.xml` |
| stack-convention clause to callers (survey `parm_map`) | the callee's own `parm []` (every recovered parameter on the stack, callee pops) | callers compiling a stack callee under the register convention (`XOR EAX,EAX ; CALL` for `PUSH 0 ; CALL`) | — |
| `return-split`, the constant-phi tail (`return_split.rs`, `const_phi_split`) | `TEST EAX,EAX ; JZ epilogue` with the taken edge landing on a bare epilogue: this compiler returns the tested register itself as the `0` of `if (x == 0) return 0;` — the merged form has to materialize its `0` in a variable of its own | `r = 0; if (x != 0) { ..; r = 1; } return r;` — Ghidra's phi of two constants behind one shared epilogue, 12 functions | `x86_watcom_const_phi.xml` |
| `return-widen` (`return_widen.rs`, `ValueSite::ReturnValue`) | the `return-width` witness's widening carve-out (`XOR EAX,EAX ; MOV AX,[g]`): the widened return zero-extends its narrow SIGNED value, `return (uint2)iRam..;` | `short g` returned under an int declaration sign-extended (`MOV EAX,[g-2] ; SAR EAX,0x10`): FUN_000243bc | `x86_watcom_return_zx.xml` |
| `ptr-offset` (`ptr_offset.rs`, last at `ValueSite::Deref`) | the original's access at the sum's address carries the offset as its displacement (`[EDX + 0x1a]`, not an `LEA`) | `*(T *)((int4)p + k)` compiled as integer arithmetic plus an `LEA`; 118 TUs carried the form, 87 with the `LEA` | `x86_watcom_ptr_offset.xml` |
| `cmp-sign` (`cmp_sign.rs`, last at `ValueSite::Equality`/`Compare`, alone at `NegatedEquality`) | the original's extension idiom ahead of the compare on the operand's own load: `MOV r16,[..] ; AND r,0xffff` (or a register copy of that load), or `XOR r,r ; MOV r16,[g]` for THAT global; `SAR`/`CWDE`/`MOVSX` veto | a narrow SIGNED memory operand C promotes by sign where the original zero-extended (`RuleZextEliminate` dropped the IR's ZEXT): FUN_00059784, FUN_00029b50; a witnessed global casts at every compare of it | `x86_watcom_cmp_sign.xml` |
| narrow parameters (`Funcdata::narrow_params`, `narrow_params_from_evidence`) | every IR use masks the low byte AND the entry region copies the low byte into a byte register (`MOV CL,AL`) | a byte parameter the decompiler widened and masked (`param_1 & 0xff` → `uint1 param_1`): FUN_00019e38 and siblings, 19 TUs | `guard_contract` (no fixture: the raw pipeline types a byte-only parameter `uint1` by itself) |
| `cmp-order` on globals (`CmpOperand::Mem`) | the `CMP`'s bare memory operand names the source's right-hand side | two globals compared, printed mirrored: FUN_00014990, FUN_000149b8 (20 TUs carry a differing global `CMP`) | `x86_watcom_cmp_mem.xml` |
| `load-hoist` (`load_hoist.rs`, a setup pass over `force_explicit`/`force_implied`) | the original's load at the load's address reads the frame through a scaled index, no `LEA` at the pointer's address | an explicit pointer temp into a frame array whose load is inlined after the index advances: the 0x2a75c trio (`uVar = auStack[i]; i++; *(..) = uVar;`) | `x86_watcom_load_hoist.xml` |
| `return-split`, the branch form (`return_split.rs`, `Site::Return`) | the original branches over the constant right after the compare (`TEST AL,AL ; JZ ; MOV AL,1`), no `SETcc` | a lone `return cVar1 != '\0';` the decompiler collapsed from `if (f() == 0) return 0; return 1;` (FUN_0002a228); the [if]+[bool return] shape now sees through the branch's BOOL_NEGATE and past heritage's return copies (FUN_0002a31c, FUN_0002ac70, FUN_00020790) | `x86_watcom_branch_ret.xml` |
| `store-forward` (`store_forward.rs`, at `ValueSite::CallArg` after mask-cast) | the call's window stores the global then reloads it (`MOV [g],AX .. MOV AX,[g]`) | an argument that is the value just stored to a global, named by the value (`g = h; f(h);`): FUN_00014214, FUN_00014240 (28 functions carry a differing global load) | `x86_watcom_store_fwd.xml` |
| `testmem` on globals (`testmem.rs`, `render_global` at `ValueSite::VarEntry`) | the original's memory-direct `TEST byte ptr [g],imm` at the mask's address | a narrow global masked into a zero-test (`(uRam & 8) != 0`) prints as the int-wide access `*(int4 *)&uRam`: FUN_00037280 (7 near functions carry the row) | (the LOAD half's axis and witness, unchanged) |
| two-width global declaration (survey `gsizes`) | the function's own bytes read the address at the wider width, the dword trick (`MOV EAX,[g-2] ; SAR EAX,0x10`, possibly scheduled apart) excluded | a read-only global read at two IR widths declared at the narrowest: FUN_000377a4's divisor, FUN_00037280 | (survey rule; probed) |
| narrow `switch` range case list (`sparse_switch.rs`, `try_emit_narrow_switch`) | the switch's own range check `CMP r16,top ; JA` (an LE-kind jump whose immediate IS the top, 0 ≤ top ≤ 3) under Ghidra's `x < top+1` | `case 0: case 1:` on an unsigned 16-bit selector printed as `if (*p <= 1)` (which compiles at int width): FUN_0002bb98 | `x86_watcom_switch_range.xml` |
| `return-split`, the early-return shape (`return_split.rs`, `Site::ListTail`) | the guarding `JZ` (after a `TEST` of the return register) lands on the BARE epilogue past the shared `XOR EAX,EAX` — the same byte fact as the constant-phi shape (`const_phi_returns_from_evidence` over `early_return_candidates`) | `if (x != 0) { .. } return 0;` printed as `if (x == 0) { return 0; }` + the body un-nested: FUN_000367a8, FUN_000184b0 (both had ZERO root rows — the jump target was the whole divergence) | `x86_watcom_early_return.xml` |
| `counted-loop` (`counted_loop.rs`, a setup mark the do-while emission asks first) | the original iterates the loop variable's register right before the loop's compare, and a CALL sits right before the iterate (`CALL ; INC EBX ; CMP EBX,4 ; JLE`, `counted_loops_from_evidence`) | a constant-start, constant-step, constant-bound do-while whose trailing `i = i + 1;` the compiler hoists above the call — printed as the `for` loop (the test on the initializer proved true at print time): FUN_0003e858, FUN_0003e7ec | `x86_watcom_counted_loop.xml` |
| tail-return-write MARK (`Program::tail_return_writes` → `Funcdata::tail_return_write`, kept by `recover::check_output_trial_use`) | every return path writes EAX from a register right before the epilogue (`MOV EAX,EDX ; POP .. ; RET`, `tail_return_write_from_evidence` over the function's OWN extent) | a function that fills a buffer AND returns it: the port's `ancestorOpUse` gate (Ghidra's too) discards a return value that is also consumed elsewhere and prints `void` — FUN_0004984c (one row from EXACT), 122 functions marked | `x86_watcom_dead_return.xml` |
| reorderer OFF per function (flags rule `Evidence::immediate_store_after_cleanup` → `-onatmil` for `-onatx`) | a constant dword store to a global within two instructions after a stack cleanup (`ADD ESP,8 ; MOV dword ptr [g],1`) — the form `-or` never leaves (it lifts the constant into a free register above the cleanup) | two source modules built without the instruction reorderer: FUN_00051764, FUN_00068789, FUN_000692f0, FUN_0006ae98 (the two-way recompile of the corpus found 8 such functions in contiguous runs; this shape names 4 of them with no counterexample among the 342 EXACT functions that need `-or`) | unit test `an_immediate_store_after_a_cleanup_drops_the_reorderer` |
| per-site constant-argument adoption (survey `constant_arg_sites`, JD decision 2) | the callee's register-only recovered arity licenses the drift AND the site's own bytes materialize the constant into that parameter register right before the call (`MOV EDX,-2 ; CALL`, no call or branch crossed) | a whole-function candidate held by its call shapes (a materialized return the next call consumes, a consumed return widened) still lends the landed function its constant extra arguments, site by site: FUN_00033668's `func_0x000596b0(g, 0xfffffffe)` | round-measured; the function-level witness alone (e41) lost FUN_00040490 to the Y-series' `func_0x00050108(0x3c, 0x1cc, 0x21330)` |
| argument carry (survey `carry_arg_sites`) | two consecutive direct calls, `from` positional and passing beyond its recovered arity, `to` register-only; every extra register `from` passes is preserved by `from` (its recovered `modify` set), unwritten between the two calls, and (constants) materialized before `from`; the two calls separated only by argument-register setup, never a store; the carried slot within `to`'s WITNESSED arity (its widest landed call site — the use-based proto under-recovers, 0x16bdc reads eax/edx/ebx but its proto shows 2) | the decompiler attributes register setup before a call to that call; the bytes attribute it to the NEXT call. `f1(x, 8, 0x14); f2();` is `f2(f1(x), 8, 0x14)` when f1's arity is 1 and f2 reuses f1's preserved registers: FUN_00030ca0, FUN_00034370, FUN_0004c364, FUN_0004cdc0, FUN_0004d1a0, FUN_0005da30 | round-measured (e46); the `--only` probe is unfaithful here (it omits the caller-side `modify` pragmas), so the corpus round is the arbiter |
| reorderer OFF per function, second witness (`Evidence::unscheduled_load_pair` → `-onatmil`) | a window keeps an indexed load immediately ahead of an independent `[ESP+k]` load that the corrected scheduler model swaps (indexed operand 3, stack temporary 0, bottom-up takes the heavier first) | FUN_00068bca, FUN_0006b496 (byte-exact only without `-or`), FUN_00069430 (up), one foreign function at sim 0.115 either way | unit test `an_unswapped_indexed_and_stack_load_pair_drops_the_reorderer` |
| narrow `switch` + tail clause (`sparse_switch.rs`, `try_emit_narrow_switch`) | the leading clauses are witnessed 16-bit register compares; ONE trailing clause that reads memory (a global, or a load inlined at the compare — `clause_reads_memory`) prints as an `if` inside the innermost case | a byte global's test after the two message compares, `if ((*p == 9) && (p[1] == 5) && (g != 0))`: FUN_0003ec58 (a register-local tail measured 10 downs in the dispatcher chains, round e30 — gated) | `x86_watcom_switch_tail.xml` |
| far return (`Funcdata::far_return`, `far_return_from_evidence`) | every return a `RETF` | one far-called handler, FUN_00058840 | `x86_watcom_far_return.xml` + `guard_contract` |
| dummy stack parameters (`Funcdata::extra_stack_params`, `dummy_stack_params`) | a `RET n` on a function with no recovered parameter: n/4 unused stack parameters and `parm []` | pointer-called callbacks that ignore their argument: FUN_0004dd2c, FUN_0004e820 | `x86_watcom_dummy_param.xml` + `guard_contract` |
| dropped parameters (`Funcdata::dropped_params`, `buildconfig::phantom_params_from_evidence`) | the register of the LAST recovered parameter pushed among the function's leading saves and popped before its returns, the parameter flowing only into callees | the callee-save family: `PUSH EDX .. POP EDX` missing because the pass-through EDX was declared a parameter (an argument register is the caller's to lose; a preserved one was never an argument), 87 functions | corpus guard `guard_phantom` (0x2c160, 0x11f18) |

The dropped-parameter fact has no self-compiled fixture: a callee stub of the generator never
reads a second register, so no MVE recovers the phantom; the byte half of the witness
(`preserved_registers`) is unit-tested and the two specimens are pinned as an EXACT guard set in
`scripts/corpus-gates.tsv` (gate 7).

Two corrections rode along, both value-preserving and both measured:

- A promoted sign-extension re-signs its operand at its own width unless the operand's C type is
  already that signed type: `(int4)xStack_18._2_2_` zero-extends in C (the accessor the emitter
  makes compilable is `*(uint2 *)..`) where the IR and the original's `MOVSX` sign-extend — wrong
  code in 21 sites / 18 TUs of the split-point family.
- A promoted zero-extension prints bare only for an operand C's own promotion widens faithfully
  (a variable, a load, a cast, a boolean, a mask, a call result); an OVERFLOWING arithmetic
  operand (add, subtract, multiply, shift left, negate, divide) keeps the `(uintN)` cast, because
  its narrow IR width is Ghidra's subvariable narrowing of a 32-bit computation the original
  truncates (`(cond) + 0xbf8` masked with `AND EAX,0xffff`). Casting more than that measured
  negative (round e4: the mask on a call result, −0.23 on one function).

## What the rounds said

| round | change | EXACT | WGSS (structural) | notes |
| --- | --- | --- | --- | --- |
| base `c0ef3d3` | — | 876 | 0.6247 | |
| e1 | every sub-int zext cast | 874 | 0.6240 | −3/+1: the cast is right only where the original widens 16-bit — hence the witness |
| e2 | + witnessed zext, cmp-order, narrow switch, sext re-sign | 910 | 0.6275 | 34 up, 0 EXACT lost; cmp-order and the switch over-fired in compound shapes |
| e3 | leaf-only cmp-order, complement literal sign, byte return, snapshot widened | 920 | 0.6276 | 1 EXACT lost to a snapshot of a written global |
| e4 | zext leaf rule, stack store order, passthrough-neutral byte return, elsewhere-gate dropped | 918 | 0.6281 | the written-global test counted heritage's return copies |
| e5 | returned variable retyped, snapshot fixes | 925 | 0.6288 | |
| e6 | snapshot writes through renamed uniques, marker-transparent store runs, either CMP operand decides the mirror | 932 | 0.6291 | landed `974d872` |
| e7 | the promotion rendering moved out of printc (`ext_cast.rs`), accessor re-sign | 936 | 0.6292 | landed `4e987bf`; identity except the 25 accessor TUs |
| e8 | mask-cast, stack clause to callers | 944 | 0.6286 | 19 downs: the mask witness matched any earlier AND on the register |
| e9 | the mask must be the register's last write before the call | 944 | 0.6306 | |
| e10 | dropped (phantom) parameters | 950 | 0.6320 | 3 downs in a three-level pass-through chain (0x2f650 → 0x2f5e4 → 0x2f474): the freed register re-allocates |
| e11 | constant-phi return split, first cut | 950 | 0.6321 | fired on 4 of the 12 carriers: the recognizer wanted a Basic condition block and a COPY into a unique |
| e12 | the condition component's exit block, any COPY of a constant | 952 | 0.6322 | 6 up (FUN_0002c4e4, FUN_0002d4ec EXACT), 1 down (FUN_0006f94c −0.012); the 0x2a75c trio keeps a pointer-temp loop row |
| e13 | return-widen + a first `cmp-sign` (any zero-extension idiom before a compare) | 951 | 0.6317 | 24 down: the `XOR r,r ; MOV r16` pair is this compiler's equality load for either signedness — three EXACT lost to the cast |
| e14 | `cmp-sign` limited to memory operands | 952 | 0.6322 | still ±1: a pair loading the OTHER operand (FUN_0004753c) |
| e15 | ptr-offset, far return, dummy stack parameters, `cmp-sign` keyed by global | 960 | 0.6361 | 84 up / 20 down: ptr-offset +4 EXACT over 121 TUs (76 up / 18 down), contracts +3, return-widen +1; `cmp-sign` +1/−1 and NOT landed |
| e16 | `cmp-sign` on the negated-equality path too | 962 | 0.6361 | +2 (FUN_0004753c back, FUN_00059784); FUN_0002dfb0 −0.258: the negated seam had let `unsigned-cmp` re-spell `param_4 != -1` |
| e17 | `NegatedEquality` seam answered by `cmp-sign` alone | 962 | 0.6362 | 0 down: `cmp-sign` landed |
| e18 | narrow parameters, the mask witness on the register's own last write | 966 | 0.6366 | 19 TUs, 11 up / 2 down, +4 EXACT (FUN_000192e8 and the 0x19e38 trio); the witness fix changed no TU |
| e19 | `cmp-order` on global operands | 968 | 0.6367 | 8 TUs, 4 up / 1 down, +2 EXACT |
| e20 | `load-hoist` (scaled frame index) | 971 | 0.6367 | +3 EXACT (the 0x2a75c trio), 0 down |
| e21 | `load-hoist` on a stepped base pointer too | 971 | 0.6367 | 3 downs, no flip (FUN_00022638 −0.083: the value takes a scratch register, the original's lives in ESI) — not landed |
| e22 | the scaled-index witness alone | 971 | 0.6367 | identical to e20 |
| e23 | `return-split`: negation-aware bool shape, the lone return's branch form | 975 | 0.6369 | 9 TUs, 6 up / 1 down, +4 EXACT |
| e25 | `store-forward` | 976 | 0.6369 | 2 TUs, +1 EXACT, 0 down |
| e26 | `cmp-sign`: the load pair over an inline load, constants at the operand's width | 977 | 0.6370 | 20 TUs, +1 EXACT, 0 down |
| e27 | `testmem` on globals | 978 | 0.6372 | 14 TUs, +1 EXACT, five MISMATCH → SAME_SHAPE, 0 down |
| e28 | a read-only global read at two IR widths declared at the wider one (own-bytes witness) | — | — | REFUTED as cut: +2 EXACT but −3 (FUN_00045aa4, FUN_00045ee0, FUN_0004f580) and 13 downs over 35 TUs — the losers' "wide read" was the dword trick reading two bytes below a short |
| e29 | the same rule with the dword trick excluded (3-instruction lookahead) | 980 | 0.6373 | 14 TUs, 7 up / 7 down (largest −0.047), +2 EXACT, 0 lost — landed |
| e30 | the narrow switch with a tail clause, ungated | — | — | +1 EXACT (FUN_0003ec58) but 10 downs in the dispatcher chains (a register-local tail, FUN_00047594) — gated to memory-reading tails |
| e31 | the tail clause gated to a memory-reading clause | 981 | 0.6374 | 2 TUs, +1 EXACT (FUN_0003ec58), 0 down — landed |
| e32 | the range case list `case 0..top:` on a witnessed `CMP r16,top ; JA` | 982 | 0.6374 | 1 TU, +1 EXACT (FUN_0002bb98), 0 down — landed; ungated (e32) it reached two register locals, one −0.066 |
| e34 | caller-side `parm []` propagation: a stack-convention callee's byte parameter meets the caller's 4-byte pushed argument (arity gates, width does not) | 983 | 0.6374 | 1 TU, +1 EXACT (FUN_00030dc8), 0 down — landed; pinned by `guard_contract 0x30dc8 EXACT` |
| e35 | `return-split`, the early-return shape | 985 | 0.6374 | 3 TUs, +2 EXACT (FUN_000184b0, FUN_000367a8), 0 down — landed |
| e36 | the printer's negation looks through an implied COPY (Ghidra's negate token descends `pushVn`): `!(x != 0)` → `x == 0` | 986 | 0.6376 | +1 EXACT (FUN_00025cb4), WGSS +0.0002, 7 sim downs (largest −0.044, comma-form clauses whose SETcc polarity moved) — landed |
| e37 | `counted-loop`: a counted do-while printed as the `for` loop under the iterate-after-call witness | 988 | 0.6376 | 12 TUs, +2 EXACT (FUN_0003e7ec, FUN_0003e858), 0 down — landed |
| e38 | a dword-immediate veto in the volatile model (an original `MOV dword ptr [g],imm` after a predecessor ⇒ not volatile) | 988 | 0.6376 | +0, 4 TUs: the register-pair store the veto targeted survives without `volatile` — REVERTED, premise refuted |
| e39 | the tail-return-write mark | 994 | 0.6380 | 26 TUs, +6 EXACT (FUN_0004984c, FUN_0004debf, FUN_0005bcf8, FUN_0005d538, FUN_0005d644, FUN_000655c0), 0 lost, WGSS +0.0003, 8 sim downs (largest −0.086, FUN_00075147) — landed |
| e40x/e40y | the whole corpus under `-onatmil` (no reorderer) and `-onatr` (no `m/i/l`), all 2803 units fresh (~340 s each) | 660 / 984 | — | measurements, not rounds: 8 functions want `-or` off (two address runs = source modules), 342 want it on; 7 scattered want `m/i/l` off, 17 want them on; a neighbourhood predictor from the scheduler model fails blind (best +7/−177) |
| e40 | the reorderer-off flag rule on the four witnessed functions | 998 | 0.6380 | 4 TUs, +4 EXACT (FUN_00051764, FUN_00068789, FUN_000692f0, FUN_0006ae98), 0 lost, 0 down — landed |
| e41 | per-site constant-argument adoption with the candidate's function-level constant witness | 998 | 0.6381 | 39 sites, +1 (FUN_00033668) −1 EXACT (FUN_00040490) and two SAME_SHAPE → MISMATCH — VETOED, the witness must be the site's own materialization |
| e42 | the same with the per-site materialization witness | 999 | 0.6381 | 8 sites, +1 EXACT (FUN_00033668), 0 lost, WGSS +0.0001, 1 sim down (FUN_00049a20 0.984 → 0.952: the adopted constant is right, its materialization hoists above a preserving call) — landed |
| e43 | scheduler model corrected from the Open Watcom source: a stack temporary carries no stall weight (`N_TEMP`), only value-operand registers count (`InsStallable`) | 996 | 0.6379 | −3 EXACT (FUN_0002d60c, FUN_00045708, FUN_0005f5c0), 40 TUs, through the volatile recovery calibrated on the old weights — VETOED, reverted |
| e44 | the second reorderer witness (the unswapped load pair) on the four flagged functions | 1001 | 0.6381 | 2 TUs, +2 EXACT (FUN_00068bca, FUN_0006b496), 0 lost, 0 down — landed; the corpus crosses 1000 |
| e45 | argument carry, first cut | 1007 | 0.6383 | +6 EXACT (FUN_00030ca0, FUN_00034370, FUN_0004c364, FUN_0004cdc0, FUN_0004d1a0, FUN_0005da30), 0 lost, 3 sim downs — one, FUN_0002a6e0, was WRONG CODE: `fill=Same` rendered `f(param_1, param_1)` where the consumer takes the prior return in ECX. Superseded by e46 |
| e46 | argument carry, `fill=Same` removed (no win used it) and the consumer register kept POSITIONAL (the caller externs `to` with a `modify` pragma only, so slot i is the i-th positional register — the callee's own `parm [..]` clause is not what the caller renders) | 1007 | 0.6383 | +6 EXACT (as e45), 0 lost, 2 sim downs, both correct-code churn in already-MISMATCH functions (FUN_0001755c 0.746→0.662 — its `0x17530` in EBX is slot 3's positional register, matching the original `MOV EBX,0x17530`; FUN_00033efc 0.761→0.758) — landed |
| e24 | the witnessed narrow zext cast SPELLED (`(uint2)x`) + the tier-2 widening gate opened to computed narrow loads | — | — | REFUTED, not landed: the spelled cast reached 131 TUs (33 up / 43 down, +1 −3 EXACT) for a 15-function family — the `XOR xH,xH` window witness cannot tell which register it zeroes; the opened tier-2 gate reached 424 TUs (58 up / 119 down, −20 EXACT): a widened local re-allocates far beyond its own load |

The scrutinee-compared-elsewhere gate on the narrow switch was measured and dropped: declining a
one-case switch whose scrutinee has other compares cost −0.70 sim over 47 TUs (the fragment
recompiles closer than the `if` more often than not). The corpus-gate rows the switch moved are
re-stamped in `scripts/corpus-gates.tsv`: two chain TUs (0x14b44, 0x3d470) left the chain set
after improving, three switch-label counts grew by one.

## The design review of the push (2026-09-04) and its four items

mosura reviewed the range `974d872..934c4e9` on design and long-term viability (stay close to
Ghidra, adapt per compiler). Verdict: the two-pass witness protocol, the printer surface (18 fields
before and after eight new arms), the protected sweep instrument and the fixture provenance are the
load-bearing parts; four things would not survive a second target unchanged. All four landed,
byte-neutral against the e42 tree (re-emit + diff, 0 differing units), suite once per batch:

| item | what changed | commit |
| --- | --- | --- |
| F4 facts | `Evidence` proves named `Fact`s (`Frame`, `SavesBeforeFrame`, `PrePentiumTuning`, `NoReorderer`); a `Rule` is `when: Fact` — the two reorderer shapes are one rule; `buildconfig::recover` shares `Profile::apply_rules` (its own copy applied two rules) | `afe3388` |
| F3 fixpoint | `recovery::derive` applied once more under the decisions in debug builds or `--debug fixpoint`; a decision the third render INTRODUCES is named on stderr. Corpus: 183 functions grow (171 `widen_local_reps`, 11 `complement_sites`, 1 `cmp_order_sites`; 37 EXACT today) — the tier-2 widening does not converge at two rounds; counted as any difference it was 217, mostly consumed candidates | `ecacc7e` |
| F1 registry | `EmitReport`/`RecoveredChoices` left printc.rs for `emit::arms::registry::{Report, Recovered}`, one typed sub-struct per arm in its own module, the R2b backlog as `arms::port`; printc keeps the two names as aliases and holds two opaque fields | `04fca4e` |
| F2 switch | `war2_survey --arms-off <arm>,..`: `Recovered::switch_off` empties the named arm's witnessed decisions (`Off`, arm-owned: `port` switches the backlog as one block so a widened declaration never outlives its rendering); the manifest's `arms:` line is stamped `; off: ..`. Measured: `--arms-off cmp-sign` changes exactly the 22 units that arm decided, each compare reverting to the port's rendering, stamp on the manifest and on stderr | `F2` |

The suite run once for the batch found two defects of the push itself, fixed in `337e83f`: the
branch-return form had made `return_split` a second owner of `SiteKind::Return` (now the one owner,
chaining to `struct_return::render_return`), and two pinned gate sets had grown without their test.

mosura's review of the batch (channel seq 1563) confirmed the four items — printc.rs's arm-named
fields went 43 (`974d872`) → 63 (`934c4e9`) → 0 — and added three findings, all landed:

- **The Return site's owners are in the table again** (`8a10d8f`): 337e83f had restored the
  one-owner invariant with a cross-arm call; both arms declare `Return`, `SHARED_KINDS` documents the
  owner order (`return-split` before `struct-return`) and the test asserts it.
- **The fixpoint check compares each arm's own decisions** (`3d2e3f0`): `Grown` per `Sites`,
  `Recovered::grown_over` destructuring the registry without `..` (a new arm is a compile error until
  compared), the same destructuring backing the ARMS completeness test, and `Fact::ALL` guarded by an
  exhaustive match. The widening compares its decided candidates' ADDRESSES (`port::Sites::widen_local_pcs`),
  not representative indices a re-render can renumber.
- **The re-keyed count, in both units** (mosura's caution, seq 1565): old instrument 183 growers = 171
  rep-keyed widening + 12 address-keyed (11 `complement_cmp`, 1 `cmp_order`); new instrument 179 pc-keyed
  widening growers, and the 12 address-keyed ones held exactly (12 of 12) — so the instrument did not narrow and the widening
  figure is a measurement.

The residual mosura named stands: printc.rs still names each arm once, at setup (13 `recognize` calls
across three construction phases with four signatures) — one line per arm, not two struct fields; and
`Fact` is one global enum a second compiler would extend.

## What did not work (probed, not built)

- The sound family (16 functions, `ADD EDX,k ; MOV EAX,EDX` for `return (rand() >> 8) % 4 + k`):
  no C form found — temporaries, `+=`, 8/16-bit return types, operand order, `-3r`/`-4r`, `-od`
  all compile to the `LEA`. The PSX source writes `ack1 += (rand() >> 8) % (ack2 - ack1 + 1)` on a
  `UWORD` parameter, which under this compiler still folds into `LEA`.
- The AIL-region constant store (`MOV EBX,1 ; MOV [g],EBX` for `g = 1`, 5 third-party functions):
  not volatile, not a flag (`-ot`, `-os`, `-od`, `-oe`, `-3r`, `-4r` all keep the register form).
- The byte-global argument loaded into `AL` first (`MOV AL,[g] ; XOR EDX,EDX ; MOV DL,AL` for
  `f(g, k)`, the 0x39430 sextet): twelve source forms — the snapshot temp at every width and
  sign, a prototyped callee (`uint1`, `char`, `uint4` parameters), the swapped argument order
  with and without the `parm` clause, a `(uint4)` cast — all compile to `MOV DL,[g]` with or
  without `AND EDX,0xff`; the `AL` staging has no C form found.
- A constant the original keeps in a register across a call and stores from it
  (`MOV [0x88bcc],EDX` after the call took `0x2c160` in EDX, FUN_0002c204; 13 functions store a
  register where the recompile stores the immediate): a local holding the constant is
  propagated back into the immediate by this compiler.
- The sound family (`ADD EDX,k ; MOV EAX,EDX` for `return rem % 4 + k`, 14 functions) is not a
  flags matter either: `-os`, `-onasx`, `-onax`, `-ot`, `-oe`, `-ol`, `-oi`, `-onalx` and no
  `-d1+` all keep the `LEA` (or change unrelated code). Closed.
- A 16-bit unsigned division (`XOR BH,BH ; XOR EDX,EDX ; DIV BX` for `600 / byte`, the
  0x167b8 quintet and 7 functions): `(uint2)600 / (uint2)b`, `600U / (uint2)b`, `(uint4)600 / b`
  and 16-bit temporaries all promote to a 32-bit `IDIV`/`DIV`.
- The argument-setup order of a constant beside a function input (`MOV EAX,ECX ; MOV EDX,k` vs
  ours the other way, FUN_0004cdc0/FUN_0004d1a0): admitting the input as reorder-safe and
  permuting the call prints the recovered `parm [edx] [eax] [ebx]` order, and the bytes do not
  move — the scheduler orders the two independent moves; the arm change was reverted.
- A zero the original reuses across a call (`XOR EDX,EDX ; CALL f ; MOV DL,AL` with `f`
  declared `modify [eax]`, FUN_000498a0; the callee-preserved zero as the next argument,
  FUN_00056db4): this compiler re-zeroes from our C even with the precise clobber list.
- The sign-extended short global loaded `MOV AX,[g] ; CWDE` (FUN_0005dfa8; the `SAR` idiom family
  is 151 functions on our side): our `(int4)iRam..` compiles to the dword trick
  (`MOV EAX,[g-2] ; SAR EAX,0x10`) under every form tried — an `extern` declaration, a 16-bit
  temporary (`MOVSX EAX,CX`), the bare global, a deref of the absolute address with and without
  `volatile` (`MOVSX EAX,[ECX]`), and the flags `-os`, `-onasx` (`MOVSX EAX,word ptr [g]`),
  `-onax`, no `-d1+`. Closed.
- A top-of-function copy of a byte global the original loads at the use (`xVar1 = xRam000846ea;`
  hoisted, FUN_0001d758, 59 functions reload a byte global): printing it inline frees the
  register the original held it in (`PUSH EBX .. MOV EBX,EDX .. POP EBX` lost, 3 rows worse).
  The `unsnapshot` arm was built, probed, and removed.
- The byte register zeroed then stored (`XOR DL,DL ; MOV [..],DL` for `p[i] = 0`, FUN_00057fcc
  and the 0x2c08c loop trio): `'\0'`, a `(uint1)0` cast, a `char *` pointee, and a zero-initialized
  byte local (declared before or at the store) all compile to the immediate store.
- A callee declared to clobber a register the original saves (`PUSH EDX .. POP EDX` in a body
  that never writes it) does not make Watcom save it. The mechanism was the phantom parameter
  (the third arm above): the register was declared an argument, and this compiler never
  preserves an argument register; dropping the parameter and its pass-through brings the save
  back (FUN_0002c160, FUN_00011f18 EXACT).

## The second push (2026-09-04, evening) — from a fresh census

A fresh near-miss census over the divergence rows (root rows = every class but layout-shift and
branch-target) at 1007 EXACT: 80 functions within 2 root rows, 129 within 3, 196 within 4, 320
within 6. Each family below was settled the same way as the first push: a hand-edited probe TU
through `recompile_check --only` to find the C the original compiled from, then a witness the
survey reads from the original's bytes, then the arm; every arm is off in the reference rendering.

| arm | witness | family (f0) | probe |
| --- | --- | --- | --- |
| callee clobber, saved-for-callee (survey, `buildconfig::saved_for_callees`) | a register pushed among the leading saves and popped before every `RET` that no body instruction reads or writes — preserved only for a callee DECLARED to clobber it; every callee clause of the TU takes it | `PUSH EBX .. POP EBX` missing around a call to a callee whose recovered clobber set is `[eax ecx edx]`: FUN_0004f850, 14 carriers | FUN_0004f850 EXACT with `ebx` in the clause |
| ~~callee clobber, below-call constant~~ | a constant materialized into a register right after a `CALL`, untouched between, read as the original declaring the callee to clobber the register | REFUTED (round f5): the extra `modify` regs re-rolled allocation across the whole corpus — 62 up / 71 down, −10 EXACT net; the scheduler does not always hoist such a load, so the shape is no witness; removed | — |
| `testmem` on INDIRECT-defined globals (`testmem.rs`, `global_read`) | unchanged (the original's `TEST byte ptr [g],imm`); the candidate may be a global version heritage renamed through an INDIRECT (after a call) or a MULTIEQUAL, not only an input | FUN_000229b4's second `TEST byte ptr [0x8196c],0x1` follows a call | FUN_000229b4 EXACT |
| `inline-call` (`inline_call.rs`, a setup mark into `force_implied`) | no `SETcc` between the call and the clause's branch | a comma clause `(iVar1 = f(), iVar1 == 0)` this compiler materializes (`SETZ AL ; AND EAX,0xff`) where the original branches on the flags: 55 TUs, 50 with the extra `SETcc` | FUN_0004d0f8 EXACT, FUN_000164cc one branch-target row from EXACT |
| `for-rotate` (`for_rotate.rs`, asked first by the overflow `while( true )` emission) | the first clause's branch jumps BACKWARD (the test at the loop end): this compiler rotates a `for` and never a `while`; declined when the initializer and the bound are both constants (the compiler folds the entry test of the port's form itself) or when the iterate's block is labeled (`LAB: }`) | Ghidra's overflow loop `while( true ) { if ((A) \|\| (B)) break; .. i++ }` for a `for` with a break: 146 functions carry the top/bottom test swap | FUN_0005beb0 EXACT as `for (i = 0; i < n; i++) { if (B) break; }` |
| `narrow-cmp` (`narrow_cmp.rs`, last at `Compare`/`Equality`) | the original's `CMP` names a register or memory operand of the value's width (`CMP AL,0x8`, `CMP BX,0x1`) | a sub-int value compared against a constant, promoted and compared signed at int width (`XOR EDX,EDX ; MOV DL,AL ; CMP EDX,0x8 ; JG` for `CMP AL,0x8 ; JA`): 65 functions, 144 rows | FUN_00020220 EXACT with `param_1 <= (uint1)0x8`; FUN_00049b84's rows with `(uint2)1 < *p` |
| `signed-load` (`signed_load.rs`, at `Load` after testmem) | a `CWDE`/`CBW`/`MOVSX` within five instructions after the load | a masked 16-bit load in a zero test typed unsigned (`AND EAX,0xffff`) where the original sign-extends (the source read a `short`): FUN_0002ebd0, FUN_00043514, FUN_0002ea18 (four sites) | FUN_0002ebd0 EXACT with `*(int2 *)` |
| `table-base` (`table_base.rs`, at `Sum` after sum-order; survey declares `extern char aRam<base>[]`) | a `MOV r32,imm` / `ADD r32,imm` (never an `LEA`) whose immediate is the sum's constant or within 0x100 below it | a table element's address as a value, `idx * 0x24 + 0x8f070`, folded into one `LEA` where the original keeps the symbol as its own operand (`MOV EDX,0x8f070 ; ADD EDX,EAX`): 126 functions carry such an immediate | FUN_00013bfc, FUN_00013a9c EXACT with the symbol |
| `zero-cmp` (`zero_cmp.rs`, last at `Equality`) | the branch at the compare is `JBE`/`JA` | an unsigned zero-equality Ghidra folded from `x <= 0` / `0 < x`, branched `JZ`/`JNZ` where the original branches on the unsigned order flags: 14 functions, 19 rows | FUN_0003dd60's four sites |

Probed and not built: the sound family's `ADD EDX,k ; MOV EAX,EDX` (five more forms, all the
`LEA`); a constant the original keeps in a byte register across two stores (`MOV BL,1`, a byte
local is propagated back); a pointer temp the original computes in the argument's register
(`MOV EDX,[g] ; MOV EDX,[EDX]`, the local changes nothing); the early `return` whose epilogue the
original duplicates inline (`JNZ ; POP EBP ; POP EDX ; RET`, FUN_0004644c: neither the `while`
form nor a guarded do-while reproduces it); a read-modify-write the original does in memory
(`OR byte ptr [EDI + 0x6],0x20`) — the compound assignment compiles to the same load/op/store
through a register, so the difference is elsewhere (the callee clobber declarations letting the
recompile keep the global in a register are the suspect); a byte flag tested twice from one
register (`TEST DL,0x1f .. TEST DL,0x8`, a byte local reshuffles the allocation); the constant
argument-order swap of FUN_00021870 (a stale `EDX=1` the recompile re-materializes — the callee's
arity, not the order).

Two shapes found and left for a later arm: a two-case `switch {0, 2}` Ghidra prints as
`if (x != 0) { switch (x) { case 2: .. } } else { .. }` (FUN_000487cc EXACT as the switch, three
carriers with the `TEST AX,AX ; JBE` witness), and the three-input constant phi of an early
return nested in an else branch (`r = 0; if (c) r = f();` for `if (!c) return 0; return f();`,
FUN_0003d188, 16 carriers of the `MOV EDX,EAX ; XOR EAX,EAX ; TEST EDX,EDX` signature).


### What the rounds said (second push)

| round | change | EXACT | WGSS | notes |
| --- | --- | --- | --- | --- |
| base (master `943ccc4`) | — | 1007 | 0.6383 | |
| f1 | inline-call, testmem on post-call globals, callee-clobber-from-saves | 1013 | 0.6402 | +6, 0 lost |
| f3 | narrow-cmp, signed-load, for-rotate (gated to a constant-init/labeled-iterate decline) | 1017 | — | +4, 0 lost |
| f4 | table-base, zero-cmp | 1024 | 0.6438 | +7, 0 lost (1 SAME_SHAPE→MISMATCH: table-base on an assigned local, gated to inline sums) |
| f5 | below-call clobber (REFUTED) | 1014 | — | −10, reverted |
| f6 | signed-load fix, zero-cmp on negated compares, zero-case switch, paired 16-bit zext, tier-2 zext-to-narrow | 1029 | — | +5 but 1 EXACT regression (tier-2 widened a value feeding a signed `IDIV`) and gate 6 hit (a genuine +0.30-sim switch grew a case) |
| f7 | f6 with the tier-2 division gate + the gate re-stamp + value-phi split | **1031** | **0.6443** | +7 over f4, 0 lost, all gates OK |

The value-phi split (`x = k; if (c) x = expr; return x` → `if (!c) return k; return expr`, the
`MOV EDX,EAX ; XOR EAX,EAX ; TEST EDX,EDX` signature) reuses the constant-phi's branch-lands-on-
epilogue witness; 17 functions carry the signature, 2 are near-EXACT (FUN_0005a028 landed).

Probed and not built this push: the SETcc-plus-constant byte store (`(cond) + 0x1c` to a byte —
Watcom always materializes the bool `SETZ AL ; AND EAX,0xff`); the duplicated early-return
epilogue (`JNZ ; POP ; POP ; RET` inline — no flag variant reproduces it); the read-modify-write
in memory (`OR byte ptr [g],k` — the compound assignment still loads/ops/stores through a
register); pointer-field store order and mid-parameter phantoms (allocation-coupled).
