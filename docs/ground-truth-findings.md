# Ground-truth recompile — findings (branch `gt-recompile`)

*What decompiling our own binaries shows, read against the source. Instrument:
`recompile::groundtruth` (`cargo run --release --example gt_recompile`), per-function three-way
files under `build/gt-recompile/<program>/<function>.3way.txt` — original source, our C, aligned
instructions. Numbers from the 2026-08-23 run: host gcc 14, `-O2`, 20 programs, 70 functions,
937 original instructions, **WGSS 0.288**, 17 EXACT.*

## What the instrument removes, and what it leaves

With the compiler held fixed, the score measures the decompiler alone, and the class profile is
WAR2's: selection 23 %, extra 21 %, missing 16 %, operand-form 13 %, regalloc 10 %. Three
instrument artifacts were found and removed before reading anything (each would have looked like
a decompiler defect): unprototyped callee declarations (gcc zeroes `EAX` before every
unprototyped call — the first "extra `XOR R,R`" mass, 51 rows, was this), `extern long
syscall();` in the prelude (same mechanism), and arity mismatches between a call site and the
callee's recovered signature (now re-declared at the call site's arity, so the bytes show the
defect's true cost instead of the fallback's). Two corpus-style artifacts remain and are excluded
from the reading: the programs use `volatile` locals to defeat gcc's folding (a decompiler cannot
know `volatile`; `tables/_start` reloads `[RSP+x]` where we pass constants), and every `_start`
renders the `syscall` instruction as a call (15 missing `SYSCALL` rows / 9 functions — WAR2's
`swi`/`int 21h` is the same class).

## Mechanisms, read against source

| # | mechanism | source | our C | bytes | reach here | WAR2 |
|---|---|---|---|---|---|---|
| 1 | **callee-clobber model.** gcc `-fipa-ra` keeps a caller's value in a register it *knows* the callee doesn't clobber; the convention says every call kills it. | `sum_to`: `for (i…) acc += square(i);` — `i` lives in `EDX` across the call | `while ((int4)uVar1 != (int4)extraout_RDX)` — the counter comes back as a call-produced value, the increment is lost: **wrong code** | the loop is gone; every caller of a small leaf is affected | `cube`, `sum_to`, `tables/_start`, … (the `extraout_*` reads) | the survey recovers per-callee `modify` lists for Watcom and it is what makes WAR2's calls come out right; this says callee-clobber recovery belongs in the decompiler (P2), not in the survey |
| 2 | **return width over-widening.** The recovered return is the register's full width. | `static int l1(int x) { return l2(x) - 9; }` | `int8 FUN_…(void)` | `CDQE` after every result: 12 rows / 8 functions; `MOVSXD` at call sites 9 / 7 | all of `deepchain`, `arith` | WAR2's `return-width` family (EAX vs AL), already an axis there — the same defect one level up |
| 3 | **whole-TU facts lost by per-function recompilation.** The originals are `static` and gcc elides the ABI stack re-alignment around their calls; our one-function-per-TU makes every function external. | `static … l1` | `FUN_…` (external) | `SUB/ADD RSP,8`: 21 rows / 9 functions; `PUSH/POP RBX` | `deepchain`, every small caller | a limit of the METHOD, not the decompiler: Watcom's TU-level effects (`-oe` inlining of statics, pooling order) are the P4 "TU grouping" question; per-function recompilation cannot reach them |
| 4 | **signedness inference.** Bit operations on a parameter make it `uint`. | `classify(int x, int y)`: `y \| 256` | `uint4 param_2`: `param_2 \| 0x100` | `OR AH,1` (int) vs `OR EAX,0x100` (unsigned) | `classify` | WAR2's typing rows (operand-form / selection) |
| 5 | **argument arity at call sites.** Leftover registers read as arguments, or a parameter the callee never reads. | `dense(a, c)` | `func_0x…(7, 5, extraout_RDX, xVar1)` | extra argument moves; with mechanism 1 it is the same root | 16 of 70 functions had a call site disagreeing with the callee's signature | WAR2's `extra`/`missing` interface mass (P2) |
| 6 | **return-type disagreement.** A callee recovered as `void` whose caller uses its value. | `is_even` ↔ `is_odd` | `void FUN_…` vs `iVar = func_0x…()` | return setup missing | `recursion` | P2 |
| 7 | **constant propagation past memory the compiler kept.** (corpus artifact: `volatile`) | `volatile int a = 7` | `func(7, …)` | missing stores / reloads | `tables/_start` and all `_start`s | real only for WAR2's volatile globals (sb95: five) |

## What this says

1. The three largest mechanisms (1, 2, 5) are **interface recovery** — prototypes, return widths,
   callee clobbers — exactly the P2 class the architecture doc calls "the largest measured defect
   class, and a correctness bug rather than a cosmetic one". On this corpus it is not cosmetic:
   `sum_to` is wrong code.
2. Mechanism 1 is the decisive one for gcc-built programs and it has a known answer in this
   repo: the WAR2 survey's recovered `modify` lists. Moving callee-clobber recovery into the
   decompiler (decompile callees first, record the registers they actually write, use that set
   at the call site instead of the convention's `killedbycall`) fixes 1 and most of 5 at once,
   for both gcc and Watcom — and is the first thing this branch should build, because the
   instrument can then measure it against source immediately.
3. Mechanism 3 bounds the method: a per-function recompile can never reproduce TU-level
   decisions. For WAR2 that is a ceiling to *name* (how many functions show it), not to fix.
4. The corpus must grow toward WAR2's loss band (20–200-instruction functions, structs, globals,
   compare ladders, strings, no `volatile`) before its WGSS means anything in absolute terms; at
   937 instructions it is a mechanism finder, not a score.

## Next on this branch

- Callee-clobber recovery as a decompiler feature (mechanism 1 + 5), measured here first.
- Return-width recovery from the callers' reads (mechanism 2).
- Two or three era-style programs (no `volatile`, no `_start` shim in the scored set) so the
  size mix matches WAR2's; score `_start`/shim functions separately.

## Update (2026-08-23): the functional oracle, and the first transfer test

**Functional check.** The programs are freestanding and return their result through the exit
status, so the instrument now links every recompiled function into one program and RUNS it
against the original (`recompile::groundtruth::functional_check`: the original source compiled
once more with `static` stripped is the harness — it supplies `_start`, the data and the
source-named calls; our objects come first under `--allow-multiple-definition`; our address-named
globals map onto the original's data symbols with `--defsym`; compiler-private constants with no
symbol are DEFINED from the image bytes). Result on the 20 programs: **10 PASS, 10 FAIL** —
`arith`, `arith64`, `floats`, `fnptr`, `irreducible`, `ptrarith`, `recursion`, `strdata`,
`structval`, `varargs` compute a different result from the original. The gate now treats a
PASS → FAIL as a regression. This is the oracle the similarity score cannot be: `sum_to` went
from one wrong rendering (`extraout_RDX`) to another (an off-by-one: `iVar3 = iVar3 + 1` after
the call and `!= iVar3 + 1` in the condition) while its similarity moved by a few rows.

**Mechanism 1, acted on and measured.** `guard_calls` already downgrades a convention-killed
register to preserved when a complete walk of the callee never writes it, but refused every
register in the convention's OUTPUT list; on SysV x86-64 that is `RDX` (the high half of a
128-bit return), so the evidence was ignored exactly where `-fipa-ra` had relied on it. The
exception now holds for the PRIMARY return register always and for all return storage when the
evidence is absent, and releases secondary return storage on a complete never-written walk.
Control corpus: `cube` and `sum_to` regain their parameters (`return iVar1 * param_1`, the loop
counter back in the loop); no function's functional verdict changed (the two are still FAIL for
other reasons), and similarity fell slightly because gcc, recompiling our single-function TU,
cannot know `square`'s clobbers and must now save `R12/RBP/RBX` around the call — mechanism 3.
**WAR2 zc34 vs zc33: byte-identical, 0 movers** — Watcom's second return register was never
gated in practice. A correctness fix at zero WAR2 cost; nothing to land on master from it yet.

**Where this leaves the experiment.** Two things it has that WAR2 does not: a source to read
each divergence against, and a yes/no correctness oracle. Its list is now ten wrong programs,
each a decompiler bug with the source beside it. Its limits are also clear: gcc `-O2`'s
interprocedural optimizations (`-fipa-ra`, static-call alignment) cap what per-function
recompilation can match on this corpus regardless of the C, so its *similarity* is a weak
signal here; its *functional* verdict is strong.

## Update (2026-08-23, later): the bug-fix pass — 10 FAIL → 1 FAIL

Working the ten wrong programs one decompiler bug at a time, each classified (mosura-only code vs
a mis-port vs a harness artifact), grounded in Ghidra's source, and measured by the functional
gate. Result: **19 PASS / 1 FAIL** (`varargs`). What each one was:

| program(s) | class | mechanism | fix |
|---|---|---|---|
| `arith` (`sum_to`), `recursion` (`fib`) | mis-port | `Cover::rebuild` (cover.cc:477) extends a Varnode's cover through every consumer whose output is IMPLIED — the expression is evaluated at its consumer. mosura's `checkImpliedCover` inflate arm and the merge tests (`merge_copy`/`adjacent`/`same_storage`, `process_copy_trims`) compared PLAIN covers, so a phi input defined before a call whose argument was an implied expression of the phi's own value merged into the phi: `uVar2 = uVar2 - 2; fib(uVar2 - 1)`. | `all_covers_extended(f, explicit)` after `mark_explicit`; `check_implied_cover` tests the extended cover. |
| `recursion`, `arith64`, `irreducible` | harness artifact | the harness (`-Dstatic=`) was built with gcc's `-fipa-ra`: `_start` kept `fact`'s result in `rdx` across a call to ITS `fib`, which never touches `rdx`; our interposed `fib` (correct C, different allocation) clobbers it. | harness compiled `-fno-ipa-ra`. |
| `structval` | mosura-only (WAR2 heuristic misapplied) | the self-evidence prototype override in `analysis::decompiler` (a straight-line body that writes a convention-`<killedbycall>`/`<unaffected>` register replaces `proto_model.input/output` with the body's read ORDER and first-read WIDTHS) and the custom register-parameter append in `recover_input_params`. Both model Watcom's `#pragma aux` — a function declaring its own convention. Under SysV the ABI is fixed: `mk`'s parameters came out RSI-before-EDI, `dot`'s 8-byte inputs matched no 4-byte trial and printed as uninitialized locals. | `ProtoModel::custom_conventions` (`lang::per_function_conventions`: `watcom`, `highc`) gates both. WAR2 path unchanged. |
| `floats` | harness artifact | Ghidra's `TypeFloat::printNameBase` is `f` at every width; the harness typed `fRam0000000000402000` (8 bytes, 0.5) as `float` and read its low half as `0.0f`. | width-aware: `float4`/`float8`/`float10` (x87 literals kept as image bytes). |
| `ptrarith` | mis-port | `PrintC::pushConstant`'s TYPE_PTR arm falls through to the "Default printing" branch, which prints a pointer-typed constant WITH its type as a cast — `(int4 *)0x403040`. Without it the PTRADD arm's `base + index` was integer arithmetic: `0x403040 + n` for `grid + n`. | `render_var` prints `(T)0x…` for `Datatype::Pointer`; `Callind` keeps its own `(code *)` only for an untyped target (Ghidra's `pushPtrCodeConstant` fall-through). |
| `strdata` (`checksum`) | mis-port | `PrintC::checkArrayDeref` takes the subscript/member form only when the address Varnode is IMPLIED; an explicit address is a named variable and prints `*name`. `render_mem` re-rendered the explicit PTRADD: `param_1 = param_1 + 1; uVar1 = param_1[1];`. | `render_mem` gated on `!is_explicit(addr)`. |
| `strdata` (`slen`, `total`) | mosura-only | `explicit_trailing` had an arm "PTRADD/PTRSUB are implied even with multiple uses". `baseExplicit` (coreaction.cc:3007) has no such exemption — it only lifts the reference LIMIT for a PTRSUB of the spacebase — and `ActionMarkImplied::checkImpliedCover` still decides. `slen`'s address `param_1 + iVar3` is read at the loop's CBRANCH after the back-edge COPY redefines `iVar3`; Ghidra names it `pcVar1 = param_1 + iVar3;`, the shortcut read the incremented index. | arm retired in `explicit_trailing`/`is_mark_candidate`/`is_core_explicit`; `max_implied_ref(f, v)` carries the spacebase-PTRSUB lift. |
| `fnptr` | harness artifact | an address-of reference (`ActionConstantPtr`'s `PTRSUB(#spacebase, #addr)`, printed `&xRam…`) has no Varnode at the address, so the TU declared it at the default width 8 and `&xRam402fe0 + (which & 3) * 8` strode by 64 (SIGSEGV). | the per-TU globals map records PTRSUB references at the pointee's width (`undefined *` → `xunknown1`). |
| `varargs` | **unported subsystem → ported** | Ghidra's `LoadGuard` / `discoverIndexedStackPointers` / `ValueSetSolver` (heritage.cc:700-1200, 1563-1600; rangeutil.cc:1503-2605, plus `CircleRange::pushForward*`): a LOAD through a computed stack pointer guards the range it may read (a COPY with `setAddrForce` before the LOAD), which is what keeps the register-save-area stores alive. mosura had none of it (Task #19), so `vsum`'s six saves were dead code. | ported in bb08e77 (`valueset.rs`, heritage.rs LoadGuard section, `RuleIndirectCollapse` arm, `MapState::addGuard`). `vsum` now prints Ghidra's shape exactly — six parameters, the five saves, the indexed reads. The verdict stays FAIL and is **beyond Ghidra**: the overflow-area walk is a phi of the INPUT STACK POINTER (`register0x00000020 = (BADSPACEBASE *)(… + 8)` in Ghidra's own C), the stack pointer as data, which no C expresses without `va_list`. On WAR2 the class is small (3 TUs with a variable-indexed stack array, ~71 with stack address arithmetic, of 3,023); zc38 measures it. |

**WAR2 transfer, measured.** The merge-cover fix alone (zc35 vs zc34): **767 EXACT (+2: 2d6f8,
3ef60)**, WGSS 0.4831 → 0.4820 (−138.5 weighted, 80 up / 77 down), one MISMATCH → COMPILE_FAIL.
The downs are the same wrong-code class the control corpus exposed, now corrected on WAR2:
FUN_0006b8f0 printed `param_1 = param_1 + 0xc; if (param_1 < param_1 + iVar1)` (the end
pointer read the incremented base), FUN_0005bae4 `while (iVar1 = f(), iVar1 - (iVar1 + 0x7d) <
0)` (the call result merged into the variable it is compared against). The wrong code compiled
CLOSER to the original bytes because it used fewer registers; the similarity paid for by those
lines was not ours to keep. The COMPILE_FAIL (FUN_0006cfd0) is Ghidra-faithful — Ghidra prints
`iVar2 = (int8)iRam000a86a8; … (int4)(1000000 / iVar2)` — and an `int8` local is undeclarable on
the 32-bit target, so the emitter gained the explicit half of the int8-divide arm
(`narrow_wide_locals`: an explicit wide local that is only an int-width extension feeding the
narrowed divide declares and assigns at int width). **zc36 vs zc33 (the master baseline): 767
EXACT (+2), 3 flips all upward (2d6f8 SAME_SHAPE→EXACT, 3ef60 MISMATCH→EXACT, 46e68
MISMATCH→SAME_SHAPE), 0 verdict regressions, WGSS 0.4831 → 0.4827 (−59.2 weighted, 89 up / 90
down).** zc37 (the checkArrayDeref gate + PTRADD explicitness) is byte-identical to zc36 on WAR2.
**zc38 (the LoadGuard port) vs zc37: +26.6 weighted (WGSS +0.0002), 0 flips, 15 up / 14 down**;
the largest down (FUN_00058d54, −8) is another correction — the old C passed two spurious stack
arguments to a two-register-argument callee (`func_0x00058c48(param_3, &xStack_14, param_3,
param_4)`; Ghidra and zc38 print two). **Cumulative, branch HEAD vs master zc33: 767 EXACT (+2),
3 flips all upward, 0 verdict regressions, WGSS 0.4831 → 0.4829 (−32.6 weighted, −0.0003).**
Whether that lands on master is JD's call under the WGSS-first bar.

## Update (2026-08-23, evening): variadic recovery — 20 PASS / 0 FAIL

JD: "we should work on that remaining fail." `varargs` needed three things, two of them beyond
Ghidra and one a mis-port found on the way (b43ba63):

1. **Ghidra's `RulePushMulti` substitute loses the stack-slot address.** The rule refuses a
   spacebase phi INPUT (ruleaction.cc:1084-1085) but the substitute phi it manufactures for
   `phi(SP + c, x + c)` is `phi(SP, x)` — the forbidden shape one level down — which is why
   Ghidra's own C reads `register0x00000020 = (BADSPACEBASE *)(register0x00000020 + 8)`.
   `ActionVarargsRecovery` (varargs.rs, after the cleanup pools) restores `phi(PTRSUB(SP, c),
   x + c)`. Then `varargs::recognize` marks the function variadic when a live `PTRSUB(SP_in,
   #off)` is USED as a value at a caller-frame offset past the parameter base with no stack
   parameter at or beyond it; unclaimed slots below `off` become unnamed parameters (the
   `printf_` format string); the printer appends `...`, prints the PTRSUB's definition as
   `va_start(var, param_N)` and its uses as the variable. Each target's prelude defines
   `va_start` as the raw address of the first anonymous argument — Watcom `(char *)&last +
   sizeof(last)` rounded (the original's `lea`), gcc `__builtin_next_arg(last)`. WAR2's
   `sprintf_`/`printf_`/FUN_00050434 wrappers, which took the address of a positive-offset
   LOCAL (`&xStack0000000c`, wrong code), now read `va_start(pxStack_10, param_6);`.
2. **`RangeList::upper_bound` mis-port** (space.rs): the probe was ordered by the derived
   `(spc, first, last)`; Ghidra's `Range::operator<` compares `(space, first)` only, so
   `in_range` denied an address on a range's FIRST byte — `[0x8, 0x1fb]` did not contain `0x8`,
   the x86-64 parameter window's first slot. The stack pre-tests and `scope_addrtied` read it
   too.
3. **The register-save area as one object** (varmap.rs `coalesce_guarded_regions`, an emission
   arm): the frame region a guarded indexed LOAD/STORE walks (`LoadGuard` base through the
   analysed maximum, local frame only) is declared as ONE array. Ghidra keeps per-slot symbols
   (`aiStack_30 [2]; xStack_28; …` — its `addGuard` hint is `open` and the fixed slot hints
   win), which is layout only the original compiler guaranteed; gcc folded the cross-slot reads
   to nothing and `vsum` returned 0. Now `xunknown8 axStack_30 [6]; axStack_30[1] = param_2; …`.

`vsum` now reads as the hand-expanded `va_arg` it is — six parameters, the save array, the
`gp_offset` walk, `va_start(piVar4, param_6)` for the overflow walk — and RUNS correctly for any
argument count. **Functional: 20 PASS / 0 FAIL**, corpus WGSS 0.2784 → 0.2814.

## Update (2026-08-23, night): era-style programs — four decompiler defects from one program

The corpus grew by seven era-style programs (`structs`, `strbuf`, `globals`, `ladder`,
`linklist`, `bitops`, `fixed`: entity tables, byte strings, a global state machine, compare
ladders, an intrusive list with a global head, bit manipulation, 16.16 fixed point; 20–80-insn
functions). Six passed first time; `globals` failed, and its one FAIL carried four decompiler
defects, every one also present on WAR2:

1. **`Funcdata::opSetInput`'s constant rule** (funcdata_op.cc:108): a constant that already has a
   reader is CLONED before being wired into another op. mosura shared constant Varnodes across
   ops, and `ActionConstantPtr` considers only `loneDescend` constants — a `.bss` address read by
   two INT_ADDs stayed an integer, and the recompiled `tally` read the ORIGINAL's `scores`.
2. **`baseExplicit`'s marker-reader rule** (coreaction.cc:3073): ANY marker reader makes a value
   explicit; mosura accepted an INDIRECT reader only at the same storage, so the trim COPY on a
   passthrough INDIRECT's input (`iVar1 = param_2;` before the call) was never printed.
3. **`.bss` is loaded memory**: Ghidra's global scope resolves a `DAT_` symbol anywhere inside a
   memory block, initialized or not; mosura's `is_loaded` only knew byte-backed blocks.
4. **`Funcdata::opInsertAfter` an INDIRECT** (funcdata_op.cc:376) means after the op it is
   indirect for. The snip fix (eccdac4) had patched one caller; `Merge::trimOpOutput` was the
   other — WAR2 FUN_0002cca0 (a list push) wrote the global head BEFORE the store that must read
   the old one, `iRam = iVar1; *(param_1 + 8) = iRam;`. The redirect now lives in
   `op_insert_after` itself.

The constant-uniqueness fix then re-typed two WAR2 globals signed (as Ghidra does) and cost two
EXACT (zc42: FUN_00019344/000207b8, the 16-bit `iRam = (uint2)byte * 2` losing its cast). The
sweep named the gap and two more ports followed: `PrintC::opIntZext/opIntSext` with
`CastStrategyC::isExtensionCastImplied` (mosura printed every ZEXT bare), and
`TypeOpIntAdd::propagateType`'s INT/UINT-onto-a-constant clause (typeop.cc:1186), which is what
makes the promotion cast implied on `uRam + 0x80248`. Sweep vs the pre-session baseline: **up
1013 / down 216, +938 weighted (mean 0.9036 → 0.9115)**. Corpus: **27 programs, 27/27 PASS**.

## The 32-bit column, measured (2026-08-28, gt speed commit 3): the "21/21 PASS" was vacuous

The per-stage census of the arms oracle (gt speed commit 0) put 212 s of a 214 s plain-32 pass in
`run`: `oracle/ground-truth/src/shim.h`'s `sys_exit` had x86-64, AArch64, RISC-V and m68k branches
and an `#else` that spun forever, so under `-m32` every original never terminated, `timeout 5`
returned 124 for the original AND for ours, and `124 == 124` was the "PASS". Review R5 (b)'s
"21/21 PASS plain-32 => arms-32" measured nothing (its six NOLINKs were real: they never reached
the run). Fixed in that commit: an `__i386__` branch (`int $0x80`, exit = 1), the `#else` is now
`#error` (an unported column fails to build, never spins into a verdict), and the oracle reserves
124 -- an original that times out is `NORUN(timeout)`, ours `FAIL(timeout)` -- so a hang can never
match a hang again. The test dropped from 430 s to seconds.

The real plain-32 verdicts, first measurement of the i386 SysV path (findings, outside the arms
invariant; the arms-32 verdict equals the plain-32 one in every program, so the invariant holds):
**3 PASS** (fixed, tailcall, varargs), **11 FAIL** -- arith (orig 51, ours 0), arith64 (3, 0),
bitfields (236, 0), bitops (166, 96), deepchain (93, 69), fallthrough (86, 6), irreducible (27, 2),
nestedloop (3, 0), recursion (7, 1), sparseswitch (29, 254), structval (39, -1 = SIGSEGV) -- and
**13 NOLINK** (compgoto, dispatch, floats, fnptr, globals, ladder, linklist, ptrarith, strbuf,
strdata, strloop, structs, tables: the i386 callee-resolution class below, seven more than before
because the exit shim changed every program's code and its clone addresses). Not PIC: the build is
`-static -no-pie -nostdlib` and the 32-bit ELFs carry no PC thunks.

ONE cause for all eleven (a hypothesis for JD, read off the objdump and the emitted TUs): gcc
`-m32 -O2` passes the arguments of LOCAL functions (static, not address-taken) in EAX/EDX/ECX --
its register convention for local i386 functions -- while the i386 cspec models the stack cdecl
only. In every FAIL program the failing callees are called with those registers loaded right
before the `call`, read them in their first instruction, and are decompiled with a `(void)`
signature: arith `square` (`imul %eax,%eax`), `cube`, `sum_to` (`test %eax,%eax`); arith64
`mul64` (`imul %edx,%eax`), `divmod64`, `rot64`; bitfields `pack`, `pun`; bitops `popcount`,
`sar_mix.constprop.0`, `extract.constprop.0`; deepchain `l1`; fallthrough `ft` (`cmp $2,%eax`);
irreducible `sm`; nestedloop `nest`; recursion `fact`, `fib`; sparseswitch `classify`
(`cmp $0x3e8,%eax`); structval `mk` (its `dot` takes the stack). The argument then appears in the
body as a local the function never assigns (`sum_to`: `if (0 < iVar1)` with `iVar1` uninitialized)
-- so ours computes on whatever the register or slot holds: 0 in six programs, garbage routed
through the switch in sparseswitch (254), and in structval a struct-by-value return on top of it
(the SIGSEGV; the twin build's split-local / struct-return class). No `in_EAX`/`in_EDX`/`in_ECX`
appears in any of the 32-bit TUs: Ghidra renders a register read at entry that no parameter covers
as an `in_<REG>` input, and such a local in an emitted TU is by construction a wrong-code sign in a
gcc column (the oracle doing its job, not a defect of the TU assembly); that mosura prints an
uninitialized ordinary local instead is a second, separate finding on the printer. The question for
JD, not a diagnosis: Ghidra's `in_<REG>` needs three things -- heritage marks a free varnode read
before written at entry as an input (`Funcdata::setInputVarnode`, the `Varnode::input` flag),
`ScopeInternal::buildVariableName` spells the `in_` prefix from that flag, and when the input
varnode is merged into a HighVariable the name representative prefers the input varnode
(`HighVariable`'s representative comparison ranks `isInput()` first), which is why the prefix
survives merging. The 64-bit column does print `in_RAX`, so the representative choice on this path
is the first suspect -- but the way to know is an oracle trace on one of these functions
(`scripts/trace-diff.sh`, CLAUDE.md), not a source-reading chain. Eleven wrong-code programs in the
32-bit column are the decompiler's i386 path, plain, no arm involved -- owner: JD's call, not
baselined, not fixed in the gt speed series.

## i386 callee resolution: a call the ELF symbol table does not name (2026-08-27, review R5 b)

In the 32-bit gcc column (`Target::Gcc32`, `-m32`) six of the 27 ground-truth programs are
NOLINK in BOTH the plain and the arm-enabled pass, with the same cause: a caller TU carries an
`undefined reference to func_0x0804xxxx` -- fnptr (`apply.isra.0` -> `func_0x080490c2`), globals
(`note` -> `func_0x08049152`), ladder (`search.constprop.0.isra.0`), linklist (`alloc_node` ->
`func_0x08049118`), strloop (`count_vowels.constprop.0.isra.0`), structs
(`damage_all.constprop.0.isra.0`). The decompiler names a callee by its address when the ELF
symbol table has no function symbol there; under `-m32` gcc emits calls to targets the table does
not name as functions (the `.isra`/`.constprop` clones' entry, or a local thunk), so the emitted
name resolves to nothing at link time. The 64-bit column does not show it (its 20/20 PASS
baseline is unchanged). Plain-32 verdicts are REPORTED by tests/ground_truth_recompile_arms.rs,
never asserted against the 64-bit baseline; this item is outside review R5 (the arms are not
involved: the same six fail plain) -- owner: JD's call.

## Twin build, first runs (2026-08-27, review R5 d2): a split local, a struct-by-value return

The MVE twin build (`recompile::twin`, tests/mve_twin_build.rs) runs the MVE's own source and
mosura's decompilation of its Watcom fixture against the same recording stubs. Two MVEs differ
PLAIN (the reference rendering, no arm involved):

- **CSAVE** (`x86_watcom_callee_save.xml`): `char buf[16]` is passed to `read16(buf, n)` and the
  word at `buf + 12` is stored to a global. The decompiled text declares `axStack_18[12]` and a
  separate `xStack_c`: the 16-byte buffer is split into a 12-byte array and a word, and the
  callee's 16-byte write reaches the word only if the compiler happens to lay the two objects out
  adjacently -- gcc -m32 does not, so `gsum` stays 0. A split local relying on layout: the
  decompiled C is not the source's program.
- **SPLIT** (`x86_watcom_split_local.xml`): `GPOINT getp(void)` returns a 4-byte struct in EAX
  (Watcom returns small structs in registers); the decompiler recovers an `int` return, and with
  the callee bound to its real prototype the assignment `uVar = getp()` is a compile error --
  the binding rule (a wrongly recovered signature is a finding, never hidden) working as written.

Both are decompiler findings, outside review R5; owner: JD's call.
