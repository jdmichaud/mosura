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
| F3 fixpoint | `recovery::derive` applied once more under the decisions in debug builds or `MOSURA_RECOVER_FIXPOINT=1`; a decision the third render INTRODUCES is named on stderr. Corpus: 183 functions grow (171 `widen_local_reps`, 11 `complement_sites`, 1 `cmp_order_sites`; 37 EXACT today) — the tier-2 widening does not converge at two rounds; counted as any difference it was 217, mostly consumed candidates | `ecacc7e` |
| F1 registry | `EmitReport`/`RecoveredChoices` left printc.rs for `emit::arms::registry::{Report, Recovered}`, one typed sub-struct per arm in its own module, the R2b backlog as `arms::port`; printc keeps the two names as aliases and holds two opaque fields | `04fca4e` |
| F2 switch | `war2_survey --arms-off <arm>,..`: `Recovered::switch_off` empties the named arm's witnessed decisions (`Off`, arm-owned: `port` switches the backlog as one block so a widened declaration never outlives its rendering); the manifest's `arms:` line is stamped `; off: ..`. Measured: `--arms-off cmp-sign` changes exactly the 22 units that arm decided, each compare reverting to the port's rendering, stamp on the manifest and on stderr | `F2` |

The suite run once for the batch found two defects of the push itself, fixed in `337e83f`: the
branch-return form had made `return_split` a second owner of `SiteKind::Return` (now the one owner,
chaining to `struct_return::render_return`), and two pinned gate sets had grown without their test.

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
