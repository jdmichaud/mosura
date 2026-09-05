# Ground-truth recompile — findings (branch `gt-recompile`)

*What decompiling our own binaries shows, read against the source. Instrument:
`recompile::groundtruth` (`cargo run --release --example gt_recompile`), per-function three-way
files under `build/gt-recompile/<program>/<function>.3way.txt` — original source, our C, aligned
instructions. Numbers from the 2026-08-23 run: host gcc 14, `-O2`, 20 programs, 70 functions,
937 original instructions, **WGSS 0.288**, 17 EXACT.*

## What the instrument removes, and what it leaves

With the compiler held fixed, the score measures the decompiler alone, and the class profile is
the subject's: selection 23 %, extra 21 %, missing 16 %, operand-form 13 %, regalloc 10 %. Three
instrument artifacts were found and removed before reading anything (each would have looked like
a decompiler defect): unprototyped callee declarations (gcc zeroes `EAX` before every
unprototyped call — the first "extra `XOR R,R`" mass, 51 rows, was this), `extern long
syscall();` in the prelude (same mechanism), and arity mismatches between a call site and the
callee's recovered signature (now re-declared at the call site's arity, so the bytes show the
defect's true cost instead of the fallback's). Two corpus-style artifacts remain and are excluded
from the reading: the programs use `volatile` locals to defeat gcc's folding (a decompiler cannot
know `volatile`; `tables/_start` reloads `[RSP+x]` where we pass constants), and every `_start`
renders the `syscall` instruction as a call (15 missing `SYSCALL` rows / 9 functions — the subject's
`swi`/`int 21h` is the same class).

## Mechanisms, read against source

| # | mechanism | source | our C | bytes | reach here | the subject |
|---|---|---|---|---|---|---|
| 1 | **callee-clobber model.** gcc `-fipa-ra` keeps a caller's value in a register it *knows* the callee doesn't clobber; the convention says every call kills it. | `sum_to`: `for (i…) acc += square(i);` — `i` lives in `EDX` across the call | `while ((int4)uVar1 != (int4)extraout_RDX)` — the counter comes back as a call-produced value, the increment is lost: **wrong code** | the loop is gone; every caller of a small leaf is affected | `cube`, `sum_to`, `tables/_start`, … (the `extraout_*` reads) | the survey recovers per-callee `modify` lists for Watcom and it is what makes the subject's calls come out right; this says callee-clobber recovery belongs in the decompiler (P2), not in the survey |
| 2 | **return width over-widening.** The recovered return is the register's full width. | `static int l1(int x) { return l2(x) - 9; }` | `int8 FUN_…(void)` | `CDQE` after every result: 12 rows / 8 functions; `MOVSXD` at call sites 9 / 7 | all of `deepchain`, `arith` | the subject's `return-width` family (EAX vs AL), already an axis there — the same defect one level up |
| 3 | **whole-TU facts lost by per-function recompilation.** The originals are `static` and gcc elides the ABI stack re-alignment around their calls; our one-function-per-TU makes every function external. | `static … l1` | `FUN_…` (external) | `SUB/ADD RSP,8`: 21 rows / 9 functions; `PUSH/POP RBX` | `deepchain`, every small caller | a limit of the METHOD, not the decompiler: Watcom's TU-level effects (`-oe` inlining of statics, pooling order) are the P4 "TU grouping" question; per-function recompilation cannot reach them |
| 4 | **signedness inference.** Bit operations on a parameter make it `uint`. | `classify(int x, int y)`: `y \| 256` | `uint4 param_2`: `param_2 \| 0x100` | `OR AH,1` (int) vs `OR EAX,0x100` (unsigned) | `classify` | the subject's typing rows (operand-form / selection) |
| 5 | **argument arity at call sites.** Leftover registers read as arguments, or a parameter the callee never reads. | `dense(a, c)` | `func_0x…(7, 5, extraout_RDX, xVar1)` | extra argument moves; with mechanism 1 it is the same root | 16 of 70 functions had a call site disagreeing with the callee's signature | the subject's `extra`/`missing` interface mass (P2) |
| 6 | **return-type disagreement.** A callee recovered as `void` whose caller uses its value. | `is_even` ↔ `is_odd` | `void FUN_…` vs `iVar = func_0x…()` | return setup missing | `recursion` | P2 |
| 7 | **constant propagation past memory the compiler kept.** (corpus artifact: `volatile`) | `volatile int a = 7` | `func(7, …)` | missing stores / reloads | `tables/_start` and all `_start`s | real only for the subject's volatile globals (sb95: five) |

## What this says

1. The three largest mechanisms (1, 2, 5) are **interface recovery** — prototypes, return widths,
   callee clobbers — exactly the P2 class the architecture doc calls "the largest measured defect
   class, and a correctness bug rather than a cosmetic one". On this corpus it is not cosmetic:
   `sum_to` is wrong code.
2. Mechanism 1 is the decisive one for gcc-built programs and it has a known answer in this
   repo: the subject survey's recovered `modify` lists. Moving callee-clobber recovery into the
   decompiler (decompile callees first, record the registers they actually write, use that set
   at the call site instead of the convention's `killedbycall`) fixes 1 and most of 5 at once,
   for both gcc and Watcom — and is the first thing this branch should build, because the
   instrument can then measure it against source immediately.
3. Mechanism 3 bounds the method: a per-function recompile can never reproduce TU-level
   decisions. For the subject that is a ceiling to *name* (how many functions show it), not to fix.
4. The corpus must grow toward the subject's loss band (20–200-instruction functions, structs, globals,
   compare ladders, strings, no `volatile`) before its WGSS means anything in absolute terms; at
   937 instructions it is a mechanism finder, not a score.

## Next on this branch

- Callee-clobber recovery as a decompiler feature (mechanism 1 + 5), measured here first.
- Return-width recovery from the callers' reads (mechanism 2).
- Two or three era-style programs (no `volatile`, no `_start` shim in the scored set) so the
  size mix matches the subject's; score `_start`/shim functions separately.

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
**the subject zc34 vs zc33: byte-identical, 0 movers** — Watcom's second return register was never
gated in practice. A correctness fix at zero the subject cost; nothing to land on master from it yet.

**Where this leaves the experiment.** Two things it has that the subject does not: a source to read
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
| `structval` | mosura-only (the subject heuristic misapplied) | the self-evidence prototype override in `analysis::decompiler` (a straight-line body that writes a convention-`<killedbycall>`/`<unaffected>` register replaces `proto_model.input/output` with the body's read ORDER and first-read WIDTHS) and the custom register-parameter append in `recover_input_params`. Both model Watcom's `#pragma aux` — a function declaring its own convention. Under SysV the ABI is fixed: `mk`'s parameters came out RSI-before-EDI, `dot`'s 8-byte inputs matched no 4-byte trial and printed as uninitialized locals. | `ProtoModel::custom_conventions` (`lang::per_function_conventions`: `watcom`, `highc`) gates both. the subject path unchanged. |
| `floats` | harness artifact | Ghidra's `TypeFloat::printNameBase` is `f` at every width; the harness typed `fRam0000000000402000` (8 bytes, 0.5) as `float` and read its low half as `0.0f`. | width-aware: `float4`/`float8`/`float10` (x87 literals kept as image bytes). |
| `ptrarith` | mis-port | `PrintC::pushConstant`'s TYPE_PTR arm falls through to the "Default printing" branch, which prints a pointer-typed constant WITH its type as a cast — `(int4 *)0x403040`. Without it the PTRADD arm's `base + index` was integer arithmetic: `0x403040 + n` for `grid + n`. | `render_var` prints `(T)0x…` for `Datatype::Pointer`; `Callind` keeps its own `(code *)` only for an untyped target (Ghidra's `pushPtrCodeConstant` fall-through). |
| `strdata` (`checksum`) | mis-port | `PrintC::checkArrayDeref` takes the subscript/member form only when the address Varnode is IMPLIED; an explicit address is a named variable and prints `*name`. `render_mem` re-rendered the explicit PTRADD: `param_1 = param_1 + 1; uVar1 = param_1[1];`. | `render_mem` gated on `!is_explicit(addr)`. |
| `strdata` (`slen`, `total`) | mosura-only | `explicit_trailing` had an arm "PTRADD/PTRSUB are implied even with multiple uses". `baseExplicit` (coreaction.cc:3007) has no such exemption — it only lifts the reference LIMIT for a PTRSUB of the spacebase — and `ActionMarkImplied::checkImpliedCover` still decides. `slen`'s address `param_1 + iVar3` is read at the loop's CBRANCH after the back-edge COPY redefines `iVar3`; Ghidra names it `pcVar1 = param_1 + iVar3;`, the shortcut read the incremented index. | arm retired in `explicit_trailing`/`is_mark_candidate`/`is_core_explicit`; `max_implied_ref(f, v)` carries the spacebase-PTRSUB lift. |
| `fnptr` | harness artifact | an address-of reference (`ActionConstantPtr`'s `PTRSUB(#spacebase, #addr)`, printed `&xRam…`) has no Varnode at the address, so the TU declared it at the default width 8 and `&xRam402fe0 + (which & 3) * 8` strode by 64 (SIGSEGV). | the per-TU globals map records PTRSUB references at the pointee's width (`undefined *` → `xunknown1`). |
| `varargs` | **unported subsystem → ported** | Ghidra's `LoadGuard` / `discoverIndexedStackPointers` / `ValueSetSolver` (heritage.cc:700-1200, 1563-1600; rangeutil.cc:1503-2605, plus `CircleRange::pushForward*`): a LOAD through a computed stack pointer guards the range it may read (a COPY with `setAddrForce` before the LOAD), which is what keeps the register-save-area stores alive. mosura had none of it (Task #19), so `vsum`'s six saves were dead code. | ported in bb08e77 (`valueset.rs`, heritage.rs LoadGuard section, `RuleIndirectCollapse` arm, `MapState::addGuard`). `vsum` now prints Ghidra's shape exactly — six parameters, the five saves, the indexed reads. The verdict stays FAIL and is **beyond Ghidra**: the overflow-area walk is a phi of the INPUT STACK POINTER (`register0x00000020 = (BADSPACEBASE *)(… + 8)` in Ghidra's own C), the stack pointer as data, which no C expresses without `va_list`. On the subject the class is small (3 TUs with a variable-indexed stack array, ~71 with stack address arithmetic, of 3,023); zc38 measures it. |

**the subject transfer, measured.** The merge-cover fix alone (zc35 vs zc34): **767 EXACT (+2: 2d6f8,
3ef60)**, WGSS 0.4831 → 0.4820 (−138.5 weighted, 80 up / 77 down), one MISMATCH → COMPILE_FAIL.
The downs are the same wrong-code class the control corpus exposed, now corrected on the subject:
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
down).** zc37 (the checkArrayDeref gate + PTRADD explicitness) is byte-identical to zc36 on the subject.
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
   sizeof(last)` rounded (the original's `lea`), gcc `__builtin_next_arg(last)`. the subject's
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
defects, every one also present on the subject:

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
   other — the subject's FUN_0002cca0 (a list push) wrote the global head BEFORE the store that must read
   the old one, `iRam = iVar1; *(param_1 + 8) = iRam;`. The redirect now lives in
   `op_insert_after` itself.

The constant-uniqueness fix then re-typed two the subject globals signed (as Ghidra does) and cost two
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

## Update (2026-08-28): the `__cdecl/__regparm` merged model -- plain-32 3 PASS / 11 FAIL -> 13 / 1

The hypothesis above held and the fix is Ghidra's own mechanism, ported (branch `regparm`). gcc's
register convention for local i386 functions is what `x86gcc.cspec` models with
`<resolveprototype name="__cdecl/__regparm">` over the constituents `__cdecl`, `__regparm3`,
`__regparm2`, `__regparm1`, named by `<eval_current_prototype>`; in Ghidra:

- `Architecture::decodeProto` (architecture.cc:740) builds a `ProtoModelMerged` whose input list
  is the UNION of the constituents' entries (`ProtoModelMerged::foldIn` fspec.cc:2834,
  `ParamListMerged::foldIn` fspec.cc:1794 with `ParamEntry::subsumesDefinition`), and
  `decodeProtoEval` (:769) records it as `evalfp_current`; `setDefaultModel` (:326) marks every
  non-default model `printInDecl`.
- `ActionPrototypeTypes` (coreaction.cc:4608) starts each function on `evalfp_current`, so the
  trials of the union list are all collected; `ActionInputPrototype` (coreaction.cc:4731,
  "fixateproto", after the cleanup pool and before `ActionNameVars`/`ActionSetCasts`, :5731–5735)
  calls `FuncProto::resolveModel` (fspec.cc:3767) -> `ProtoModelMerged::selectModel`
  (fspec.cc:2877): each constituent is scored against the ACTIVE trials by `ScoreProtoModel`
  (fspec.cc:2705/2717/2738 -- an empty slot before a used one costs 16, 10, 7, 5 then 3 each; a
  slot used twice 20; a trial no entry of the model can place 20, `possibleParamWithSlot`
  fspec.cc:1360); the lowest score wins, ties go to the first constituent (`__cdecl`), a score of
  0 stops the search; no fit at all -> "No model matches" (fspec.cc:2901).
- The chosen model's name is printed in the declaration (`emitFunctionDeclaration`,
  printc.cc:2577/2584): `int __regparm3 sum_to(int param_1)`.
- Calls never see the merged model: `ActionDefaultParams` (coreaction.cc:2309–2327) gives a call
  the callee's prototype when the callee is known (`fc->copy(otherfunc->getFuncProto())`), else
  `evalfp_called`, which no shipped x86 spec names -- the default `__cdecl`.

mosura (13 files, +645/-26): `analysis::cspec` decodes `<resolveprototype>` and the two
`<eval_*_prototype>` tags (`decode_named_model`, `fold_in`), `ProtoModel { name, print_in_decl,
merged }`, `ScoreProtoModel`, `ProtoModel::select_model`, `fspec::resolve_model` run by the new
`ActionInputPrototype` at Ghidra's position in `pipeline.rs`; the call-side model is a separate
`Funcdata::called_model` (the union list's overlapping register+stack entries have no usable
`resource_start`, and a call must start `__cdecl` as in Ghidra); the recovered callee prototype
carries its model onto the call (`CallSpec::model`, `analysis::decompiler`), and the ground-truth
analysis iterates the prototype pass to a fixpoint (`recover_prototypes_fixpoint`: deepchain's
pass-through chain `l1 -> ... -> l8` resolves one level per round; Ghidra's analyzer iterates too).
The gt prelude defines the model keywords empty (`#define __regparm3` ...): the harness calls our
functions `cdecl`, so the keyword must vanish from our TU. Trace evidence: the oracle on a
self-compiled `sum_to` fixture (`x86:LE:32:default:gcc`; the fixture arch in `gt_recompile.rs` was
the fix) selects `__regparm3` in `resolveModel` and prints `int __regparm3 sum_to(int param_1)`;
ours prints the same text.

Before -> after (`gt_recompile --m32`, orig exit / ours; every callee below was `(void)` or a
stack signature before, `__regparm3` unless noted):

| program | before | after | callees whose signature changed |
|---|---|---|---|
| arith | 51 / 0 | PASS | `square(int)`, `cube(int)`, `sum_to(int)` |
| arith64 | 3 / 0 | PASS | `mul64(int,int)`, `divmod64(int,int)`, `rot64(uint,uint1)` |
| bitfields | 236 / 0 | PASS | `pack(uint)`, `pun(uint)` |
| bitops | 166 / 96 | PASS | `popcount(uint)`, `swap16(uint)` (the `.constprop` clones take no argument) |
| deepchain | 93 / 69 | PASS | `l1` .. `l8`, one argument each (fixpoint rounds) |
| fallthrough | 86 / 6 | PASS | `ft(int,int)` |
| irreducible | 27 / 2 | PASS | `sm(int,int)` |
| nestedloop | 3 / 0 | PASS | `nest(int)` |
| recursion | 7 / 1 | PASS | `fact(int)`, `fib(uint)` |
| sparseswitch | 29 / 254 | PASS | `classify(int)` |
| structval | 39 / -1 | FAIL 39 / 24 | `mk(ptr,a,b)` `__regparm3`, `dot(p1,p2,p3,p4)` `__regparm2` |

fixed, tailcall, varargs stay PASS (fixed's `fmul`, tailcall's `is_even`/`is_odd` gained
`__regparm3` and still pass: the two-argument callees are the argument-ORDER evidence -- EAX then
EDX is `param_1, param_2`). The 13 NOLINKs are unchanged (the callee-resolution class, out of this
order); their TUs also gained regparm signatures (compgoto 1, dispatch 3, fnptr 1, globals 2,
ladder 3, linklist 3, ptrarith 2, strbuf 4, strdata 2, structs 2, tables 2; floats and strloop 0)
-- movement only, unmeasured. gt-arms alone: 27 programs, plain-32 PASS 13, arms-32 = plain-32
in every program (4.0 s); the 64-bit baseline test alone: ok against master's baseline. the subject:
identity, 0 differing entries in recovered/ and raw/ (3,023 files each), corpus gates OK --
Watcom's cspec has no `<resolveprototype>`, so every Watcom function keeps its default model and
the call-side split reproduces the model every call had before.

**structval, the remaining FAIL, is another class -- the struct-by-value return.** Read off the
objects: the harness's `_start` calls `mk` with the hidden return pointer pushed first
(`push $4; push $3; push %ebx; call mk`) and then reads the result from `0x8(%esp)`/`0xc(%esp)` --
offsets that are only right if the CALLEE popped the hidden pointer (`ret $4`, the i386 SysV rule
for a memory-returned struct). Ours is `void __regparm3 mk(xunknown4 *param_1, ...)` -- a plain
pointer parameter -- and returns with `ret`; every later stack read of the harness is shifted by
one word, and `dot` is called as `dot(4, 3, 3, 4)` = 24 exactly. `dot` itself is right: gcc's
IPA-SRA scalarized `p` into EAX/EDX and left the aggregate `q` on the stack, our
`int __regparm2 dot(p1, p2, p3, p4) = p1 * p3 + p2 * p4` is the original under regparm2 and the
four-word cdecl call under the harness. The regparm selection is also right for `mk`: the
original passes the sret pointer in EAX. What is missing is Ghidra's hidden-return mechanism,
which is TYPE-driven: `ParameterPieces::hiddenretparm` (fspec.hh:363) is assigned when the return
data type needs memory storage -- `ProtoModel::assignParameterStorage` inserts the hidden pointer
into the input storage (fspec.cc:2420/2451), `ParamListStandard::assignAddressFallback` with
`TYPECLASS_HIDDENRET` (fspec.cc:792–805), the `hiddenret_ptrparam`/`hiddenret_specialreg`
response codes (fspec.cc:1583–1610), mirrored onto the symbol as `Varnode::hiddenretparm`
(fspec.cc:3156/3176/3193) and skipped by the declaration printer (`isHiddenReturn`,
fspec.cc:3455). Without a struct return type Ghidra prints exactly our `void mk(undefined4 *, ...)`
and its caller would be equally wrong; the fix is a struct-return recovery (the twin build's
SPLIT class above: `GPOINT getp(void)` returned in EAX), not the model. Open item; owner: JD's call.

## Update (2026-08-28, structval): the hidden struct return -- what Ghidra does, and the arm

The regparm round left structval as the one plain-32 FAIL (39 vs 24: the harness's cdecl caller
expects the callee-pop `ret $4` of the hidden return pointer, ours returns with `ret`). Step 1 of
the order was the instrument: Ghidra's own console (`decomp_dbg`, built from the shipped 12.0.3
source; `map function <addr> <name>` + `parse line` lock the return type through
`Architecture::setPrototype`, grammar.cc:3151) on a global cdecl twin of `mk` (`gcc -m32 -O2`;
`ret $4`), its caller, the original regparm3 `mk`, and the harness's `_start`:

    ##### A: cdecl twin mk (mk_cdecl.elf 0x8049000), return LOCKED pt mk(int4,int4)
    /data/r6-scratch/gt/sv/mk_cdecl.elf successfully loaded: Intel/AMD 32-bit x86
    Function mk: 0x08049000

    pt * mk(pt *rethidden,int4 a,int4 b)

    {
      rethidden->x = a;
      rethidden->y = b;
      return rethidden;
    }
    ##### A2: cdecl twin mk, no lock
    /data/r6-scratch/gt/sv/mk_cdecl.elf successfully loaded: Intel/AMD 32-bit x86
    Function mk: 0x08049000

    void mk(xunknown4 *param_1,xunknown4 param_2,xunknown4 param_3)

    {
      *param_1 = param_2;
      param_1[1] = param_3;
      return;
    }
    ##### C: cdecl twin call site use() (0x8049040), mk/dot locked
    /data/r6-scratch/gt/sv/mk_cdecl.elf successfully loaded: Intel/AMD 32-bit x86
    Function use: 0x08049040

    void use(void)

    {
      pt p;
      pt q;
      pt *rethidden;
      int4 iVar1;
      int4 iVar2;
      int4 iVar3;
      pt pStack_14;

      iVar2 = 4;
      iVar1 = 3;
      mk(&pStack_14,3,4);
      iVar3 = iVar2;
      mk(rethidden,5,6);
      p.y = pStack_14.x;
      p.x = iVar2;
      q.y = iVar3;
      q.x = iVar1;
      dot(p,q);
      return;
    }
    ##### B: original regparm3 mk (structval.elf 0x8049000), LOCKED pt __regparm3 mk(int4,int4)
    /data/mosura-gt/build/gt-recompile/structval.gcc32/structval.elf successfully loaded: Intel/AMD 32-bit x86
    Function mk: 0x08049000

    pt __regparm3 mk(int4 a,int4 b)

    {
      xunknown4 in_ECX;
      pt pVar1;

      *(int4 *)a = b;
      *(xunknown4 *)(a + 4) = in_ECX;
      pVar1.y = b;
      pVar1.x = a;
      return pVar1;
    }
    ##### B2: harness _start (structval.ours 0x8049080), mk/dot locked cdecl
    /data/mosura-gt/build/gt-recompile/structval.gcc32.plain/structval.ours successfully loaded: Intel/AMD 32-bit x86
    Function _start: 0x08049080

    void _start(void)

    {
      code *pcVar1;
      pt p;
      pt q;
      int4 iVar2;
      int4 iVar3;
      int4 iVar4;
      pt pStack_14;

      iVar3 = 4;
      iVar2 = 3;
      mk(&pStack_14,3,4);
      iVar4 = iVar3;
      mk(&pStack_14,5,6);
      p.y = pStack_14.x;
      p.x = iVar3;
      q.y = iVar4;
      q.x = iVar2;
      dot(p,q);
      pcVar1 = (code *)swi(0x80);
      (*pcVar1)();
      return;
    }

What it establishes: the C++ recovers nothing from these bytes (A2 = our TU); with the type locked
it prints the hidden pointer as an explicit first parameter and returns it (A: the output becomes
the POINTER type -- `<hidden_return/>` without a strategy is `hiddenret_specialreg`,
modelrules.cc:1386-1400; fspec.cc:1583-1610 types the output `pointertp` and adds the extra
input, assignMap places it through `assignAddressFallback(TYPECLASS_HIDDENRET)` -- no hiddenret
pentry in `__cdecl`'s input list, so the TYPECLASS_GENERAL stack entry takes it, fspec.cc:792-805;
printc.cc has no `isHiddenReturn` check at all -- `__return_storage_ptr__` is the Java GUI's
name, DecompilerConcepts.html "Auto-Parameters"); the call site renders with the pointer
argument, not `local = f(..)`, and goes wrong-code because `__cdecl`'s extrapop=4 ignores the
callee's `ret $4` (in Ghidra proper the Java analyzer computes the function's stack purge from
`RET imm` -- `FunctionPurgeAnalysisCmd`, `findPurgeInstruction`/`getPurgeValue` -- and ships
`extrapop = purge + stackshift`, FunctionPrototype.java:168-178; the standalone C++ has none of
it); and `__regparm3` has no hidden_return rule at all (B: an 8-byte struct goes to its EDX:EAX
join pentry), so the cspec cannot express gcc's local convention (pointer in EAX = regparm slot 0,
returned unchanged, no pop).

Ruling (fable-b, seq 526/528/530): a witnessed RECOVERY plus an EMIT ARM, the frame-fill/
struct-copy layer, behind `struct-return=ghidra|witness`, `witness` in the gt ARMS plan only --
`plain()` is the reference rendering by contract; the faithful substrate (the `<rule>` decode at
cspec.rs:787, `TYPECLASS_HIDDENRET`, `assignParameterStorage`'s hidden input, the dead
`HIDDENRETPARM` flag at varnode.rs:46) is DEFERRED until a typed struct return exists to feed it.
The design is docs/struct-return-arm.md: the fact (`analysis::sret`: slot 0 only stored through
inside [0, N) and returned unchanged -- including the void form, slot 0 = the untouched return
register), the witness (`recompile::recovery::struct_return`: the callee's own `ret $4`, or every
known call site dropping the pointer and passing a local's address, through the prototype
fixpoint), the arm (the fourth declarations-family seam `signature`, the `Return` statement site,
the ordered second answerers ahead of frame-fill with the decline rule on frame-fill's setup
state, the layout-derived tag `Datatype::struct_tag`). The caller side needs no extrapop plumbing:
callers already carry `4 + n` from `callee_cleanup` (analysis/decompiler.rs).

Result: arms-32 structval FAIL(39/24) -> PASS -- `struct s8_x4x4 __regparm3 FUN_08049000(xunknown4
param_2, xunknown4 param_3) { struct s8_x4x4 __ret; __ret.f0 = param_2; __ret.f4 = param_3; return
__ret; }` and, in our `_start`, `struct s8_x4x4 xStack_14; xStack_14 = func_0x08049000(3, 4);
xVar1 = xStack_14.f4; ..` (our `_start.c` is compiled, though not linked, so the caller half is
on the PASS path). The per-program table and the column totals are in the READY of the round
(plain-32 unchanged at 13 / 1 / 13; arms-32 14 / 0 / 13; the gt-arms invariant holds with
structval its one plain-FAIL/arms-PASS line). Open beside it: `dot`'s struct-by-value ARGUMENTS
(right as rendered, `int4 __regparm2 dot(p1, p2, p3, p4)`), and the two regparm nits landed with
this round (stackvars.rs reads the CALLED model's extrapop, coreaction.cc:264; `fold_in`'s doc
names the absent internalstorage/inject ids).

## Update (2026-09-05, closure of the productisation plan): gt-arms — one wrong-code-arm finding, pre-existing

`cargo test -p mosura --test ground_truth_recompile_arms -- --ignored` at master `d4b9cda` (the
closure of `docs/product/plan-2026-09-05.md`): 27 programs, plain-32 PASS 13, arm TUs 53/109
functions — and ONE violation of the invariant "a program that PASSes plain must PASS arm-enabled":

```
gt-arms fixed: plain-32 PASS | arms-32 NOLINK (lerp.constprop.0.c:(.text+0x20): undefined reference to `aRam00020000') | arm TUs 2/7: lerp.constprop.0 _start
```

The arm-enabled rendering of `lerp.constprop.0` (program `fixed`, `oracle/ground-truth/src/fixed.c`)
names a RAM aggregate `aRam00020000` that no TU defines, so the arm-enabled program does not link
while the plain rendering links and runs correctly. Per this test's rule the finding is listed, not
baselined and not fixed here. **Attribution:** the identical line (same symbol, same TU, same
summary) appears on `6b504a5`, the base of the plan — so the finding predates the plan's eight work
packages (which were all identity-gated at 0/3023 on the Watcom corpus) and comes from the arm work
landed between the previous gt-arms run (2026-08-28: arms-32 14 / 0 / 13, no finding) and
2026-09-05. Beside it, two `[recover] FIXPOINT VIOLATION … the third render introduces
[port.widen_local_pcs]` warnings (`FUN_08049000`, `FUN_08049050`), also present on the base.
Structval's plain-FAIL/arms-PASS line is unchanged. The rest of the 32-bit column is as on
2026-08-28 (13 NOLINK on `func_0x…` callee names).
