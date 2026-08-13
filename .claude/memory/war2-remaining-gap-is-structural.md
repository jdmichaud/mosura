---
name: war2-remaining-gap-is-structural
description: "81% of WAR2's mismatching functions differ in >40% of their instructions — the gap to byte-exactness is not a tail of small bugs, and only ~97 functions are one or two regions away"
metadata:
  type: project
---

**CURRENT: 392 byte-clean (M38, 2026-08-13, mosura `b7a5763`), COMPILE_FAIL 73.** Progression:
133 -> 372 -> 384 (M28) -> 372 (M34, a regression I caused) -> 386 -> 387 -> **392**.

**THE +5 THAT WORKED, and why:** `guard_calls` was registering a CALLEE-SAVE stack slot as an
outgoing call argument (554ac15) — Ghidra prevents this in the unported `ActionRestrictLocal`. It
also took the undefined-local class from 603 TUs to 250, 23 of which became byte-clean. It was
found by TRACING, not guessing: instrument the code that PRODUCES the output, then the point of
change, then the varnode's flags, then the COPY's source, then the original's prologue. Four guards
written before that chain were each keyed on a property the varnode did not have, and all four were
reverted; one command dumping its flags would have killed all four upfront.

**THE LOAD-EXPLICIT LEVER — RESOLVED: the port as written is INERT, and every earlier number
about it came from a STALE BINARY.**

Removing the non-Ghidra "a multi-use LOAD is always explicit" rule and porting
`checkImpliedCover`'s LOAD/CALL arms (coreaction.cc:3376) produced, in sequence:

| measurement | what it actually was |
|---|---|
| M39: 392 -> 389, "six regressions, +3 gains" | raw op index compared against ENCODED cover positions (`cover_of` writes at 2i+2, reads at 2i+1) — every rejection spurious |
| "still six regressions, +4 gains" after the encoding fix | the fix was built with `cargo build` (debug) while the emit ran `cargo run --release` — the release binary never had it |
| with the fix genuinely in the release build | **0 regressions, 0 gains — INERT** |

With correct units the arm rejects essentially every candidate: a multi-use LOAD's cover almost
always spans a CALL or a STORE, so nothing is ever implied and the port is behaviourally identical
to the blanket rule it replaces. It is not landed — no benefit, added complexity.

To make it pay, the arms need Ghidra's precision, not just correct units: `isPossibleAlias` on the
STORE side (Ghidra lets a crossing STORE through unless the pointers may coincide), and a Cover that
is a set of INTERVALS rather than mosura's one (min,max) span per block, which swallows everything
between two distant uses.

⚠️ **BUILD PROFILE:** the emit runs `cargo run --release`. Validate with a RELEASE build or the
measurement is of the previous binary. This produced two rounds of confident, wrong conclusions.

**THE REMAINING 73 COMPILE_FAILs SHARE ONE ROOT: values wider than 4 bytes.** Watcom 10.0a has no
64-bit integer type, so `prelude.h` models 8-byte values as `double`
(`typedef double uint8/undefined8`, and `CONCAT44(h,l)` expands to
`(double)(h)*4294967296.0 + (double)(l)`). Every BITWISE use of such a value is then invalid C:

    E1079 "Expression must be integral"  (19 TUs)  — e.g. `(int4)(CONCAT44(param_2,xStack_14) >> 0x10) >> 0x10`
    E1011 undeclared `int12`/`int14`/`xunknown10/12` (24) — widths with no C type at all
    E1032 `.` on a non-struct (23) — Ghidra's `._0_6_` partial field at a width `exact_uint` cannot
          render (it covers 1/2/4; a 6-byte assignment has no C spelling)

That is ~66 of the 73. **None of them is a prelude fix.** Adding a typedef cannot make a 6- or
14-byte integer exist, and widening `uint8` cannot help unless Watcom 10.0a has a 64-bit integer
type — UNTESTED; `__int64` arrived in Watcom 11, so assume not until checked.

⚠️ **AND THE OBVIOUS DECOMPILER FIX IS NOT AVAILABLE.** "Simplify the SUBPIECE-of-PIECE away" was
the first suggestion, and it is wrong: every relevant Ghidra rule is ALREADY ported —
`RuleSubExtComm`, `RuleSubCommute`, `RuleSubZext`, `RuleSubRight`, `RuleSubNormal`,
`RuleShiftPiece`, `RuleAndPiece`, `RulePiece2Sext`, `RuleSubCancel`, `RulePiece2Zext`. The 64-bit
intermediate survives because the shift genuinely crosses the 32-bit boundary of two independent
values; Ghidra produces the same thing.

**So a real part of the remaining gap is a TARGET-LANGUAGE limit, not a defect.** Watcom 10.0a
cannot express a 64-bit integer, a 6-byte assignment, or a 14-byte value, and no decompiler work
changes that. ~66 of the 73 compile failures are in that category, which puts a CEILING on what
this survey can reach: those functions cannot be byte-clean while the emitted language is C
compiled by this toolchain.

**CEILING MEASURED — AND IT IS NOT A REAL CONSTRAINT. Do not repeat this worry.** Counting the
3023 emitted TUs by construct:

| construct | TUs | of which byte-CLEAN |
|---|---|---|
| CONCAT then shift/mask (64-bit bitwise) | 88 | **36** |
| software interrupt (`swi`) | 74 | 3 |
| partial field at an inexpressible width | 22 | **22** |
| type wider than 8 bytes | 11 | **11** |
| port / cpuid intrinsic | 8 | 0 |

48 of the 171 TUs containing one of these are ALREADY byte-clean, so the constructs are not fatal
per se — they appear in expressions the emitter renders fine. The genuinely blocked set is the 73
COMPILE_FAILs, i.e. ~2% of the corpus.

So the achievable denominator is ~2950, not something much smaller. At 392 that is 13%, and a 600
target is 20% of what compiles. **Expressibility is not what blocks it** — decompiler quality on
the structural bulk is.

**WHERE THE NEAR SET STANDS AFTER THIS SESSION (M38).** It GREW from 516 to 588 functions within
40% of matching — ~72 more moved close without crossing the line, which is the clearest sign the
session's fixes were directionally right. Its divergence census:

     216  orig `mov`  -> (absent)        154  orig `pop`  -> (absent)
     159  `mov` -> `mov` (different)     130  orig `push` -> (absent)
     138  (absent) -> `mov`               71  (absent) -> `xor`
      35  `test` -> `mov and and`         24  `mov cmp` -> `movsx cmp`

`pop`/`push` deletions dominate: 284 places where the ORIGINAL saves a register and we do not.

⚠️ **I ASSUMED THAT WAS THE `modify` LIST OVER-CLAIMING AND TESTED IT — IT IS NOT.** FUN_0005a4a4:

    original  push ebx ; push ebp ; mov ebp,esp ; mov ebx,eax ; call [ebx+0x24] ; pop ebp ; pop ebx
    ours      push ebp ; mov ebp,esp ; call [eax+0x24] ; pop ebp                        (8b vs 12b)

Ours is CORRECT and SHORTER. The original does a redundant EBX save plus `mov ebx,eax` because its
register allocator parked the pointer in a callee-saved register. Our `modify [eax ecx edx]`
correctly says EBX is preserved; we simply never use it. Nothing in the C controls which register
Watcom picks, so this shape is not reachable by any declaration.

So a large part of the push/pop gap is REGISTER ALLOCATION, not a contract defect — the same
category as the `lea`-vs-`add` and `xor+mov`-vs-`movzx` instruction-selection differences recorded
above. Check a candidate against this before assuming the modify list is wrong.

**LOCALS REMAIN THE STRONGEST PREDICTOR** (rate by size band x local count, M38):

| size | 0 locals | 1-3 | 4+ |
|---|---|---|---|
| 0-40 | 47.9% | 33.9% | 0.0% |
| 41-80 | 29.0% | 4.8% | 1.1% |
| 81-160 | 10.8% | 0.7% | 0.0% |
| 161+ | 0.0% | 0.4% | 0.0% |

A 6x drop at FIXED size between 0 and 1-3 locals, in every band. Not a size confound. The
MAX_IMPLIED_REF / LOAD-explicit angle was tried (removing the non-Ghidra "multi-use LOAD is always
explicit" rule): it gained +3 on a 516-function sample but FAILED two build-time-verified
ground-truth MVEs and was reverted. That remains the most promising untried direction, and it needs
those two references re-verified rather than a blanket removal.

**WHERE THE REMAINING 99 COMPILE_FAILs ARE BLOCKED** (first error per TU, after the `swi` fix):
24 `E1011` undeclared (mostly widths C has no type for — `int12`, `int14`, `xunknown10/12`),
24 `E1052` void-typed expression, 23 `E1032` `.` on a non-struct (Ghidra's `._0_6_` partial-field
syntax at a width `exact_uint` cannot render — it covers 1/2/4 only, and a 6-byte assignment has no
C spelling), 19 `E1079` non-integral, 7 `E1063` missing operand. These now need DECOMPILER work;
the prelude-level wins are taken.

**AN EMITTER BUG WORTH REMEMBERING (fixed, 79a1aad):** `declared_locals` treated any line shaped
`<word> … <word>;` with no `=` and no `(` as a declaration, so `return param_1 - iRam00090630;`
parsed as DECLARING that global — and the emitter then skipped declaring it, leaving the TU
referencing an undeclared symbol. Statement keywords are rejected now, plus a safety net that
declares any referenced `<prefix>Ram<hex>` global nothing else declared.

⚠️ **THREE MEASUREMENTS IN A ROW WERE FICTION** (M30/M32/M33). Two causes, both now fixed:
`remeasure.sh` ran `compile.frozen.sh`, a COPY in the scratchpad, so harness fixes committed to
`war2-survey/compile.sh` never executed — M32 and M33 returned byte-identical numbers for that
reason. And `compile.sh` never cleared `obj/`, so a TU that failed to compile silently kept the
object from the PREVIOUS run and was scored as if current. compare.py now refuses stale objects,
compile.sh clears obj/ and chunks the batch at 250 (one aborting TU used to kill all 3023), and
remeasure.sh refreshes the frozen copy at run start.

**THE CHEAP VALIDATION LOOP, which should be used before every full run:** compile a SAMPLE with
`trybatch.py --idxfile <list>` (~4 minutes) instead of the full survey (~25). Running it over the
previously-byte-clean set is the direct test for regressions — it showed 389/390 recovered before
M35 was launched, where M34 had scored 375/390.

**⭐ EARLIER, at 375 byte-clean (`classify_diffs.py`, results.m20).** Both instruction
streams are aligned with difflib over normalized mnemonics; each mismatch is classed by how many
divergent regions it has and what fraction of its instructions differ.

| class | count | share |
|---|---|---|
| STRUCTURAL (>40% of instructions differ) | 2079 | 80.0% |
| NEAR/PARTIAL (<=40%) | 424 | 16.3% |
| LOCAL (1 region, <=3 instructions) | 92 | 3.5% |

(Measured at 379 byte-clean with the padding-corrected instrument. An earlier revision of this
file gave 2111/391/78/19 from a tool that compared against the UNTRIMMED original and so invented
a divergent region at the end of every padded function.)

**THE TAIL IS FLAT.** Across the 516 near functions there are **531 distinct divergent-region
shapes over 2106 regions** — about four regions per shape, and the top shapes are generic single
instruction inserts/deletes (`mov`->`-` 184, `pop`->`-` 139, `-`->`mov` 119, `push`->`-` 111),
i.e. register allocation and value materialization, not one mechanical cause. There is no large
remaining lever in the near set; wins come ~4 functions at a time.

**Only 97 functions are within one or two small regions of matching.** Reaching 600 from 375 needs
+225, so it CANNOT come from the near-miss tail — it requires converting ~46% of the 488
non-structural functions, or breaking into the structural bulk.

## What the closest 97 actually need (censused divergent regions)

    13  orig has trailing `8d 40 ..` (lea-NOP padding)   <- comparator, now fixed, gained 0
    10  orig: and eax,0xff        cand: (none)           <- byte-width parameter typing
     6  orig: mov eax,eax         cand: (none)           <- padding
     6  orig: ret                 cand: ret 0x4          <- caller-pop vs callee-pop convention
     5  orig: (none)              cand: mov ah,0x1
     4  orig: shl eax,0x2         cand: lea eax,[eax*4+0] <- peephole/instruction selection
     2  jbe/jae, jl/jle, jg/jge swaps                     <- condition-code recovery

A large share of these are INSTRUCTION SELECTION (peepholes) and comparator artefacts, not
decompiler defects. `add edx,0x12 ; mov eax,edx` vs `lea eax,[edx+0x12]` (FUN_00023210) is the
worked example: both return in EAX and the C is right; only codegen differs.

## Four hypotheses sized and KILLED with the corrected instrument (do not re-derive)

Measured on the 480 "near" functions (<=40% of instructions differ) — the ONLY population where a
convention change could flip a verdict. All report the survey's own verdict via
`compare.classify(..., objp=...)`:

| hypothesis | byte-clean |
|---|---|
| baseline (per-function flags) | 0 of 480 |
| `modify exact []` (blanket) | 0 |
| `modify exact [<precise list from the original's saves>]` | 0 |
| uniform `-onatx` / `-onatx -d1+` | 0 / 1 |

⚠️ **The instrument was broken for the first three runs of this kind.** A probe that compares
`cand == orig` cannot see compare.py's both-sided relocation masking, so every function containing
a call or a global reference reads MISMATCH and BOTH arms report zero — a negative that looks
clean and means nothing. `compare.classify` now takes an `objp` override; any probe MUST use it.

## Confounds ruled out along the way

- **"Functions preserving many registers are a class."** They are not: leading-push count is a
  proxy for function SIZE (median length 30 / 31 / 56 / 87 / 108 / 163 / 232 bytes for 0..6
  pushes). The low byte-clean rate at 4+ pushes is the low rate for big functions.
- **`modify exact []`** (Watcom's forcing form; plain `modify []` is inert) does produce the
  register saves, but sized on 120 functions it gave EXACT 0 -> 0 and mean |delta| 33.5 -> 34.0.
  Blunt instrument: it also saves registers the original does not, including `push gs`.

## The one thing that IS worth knowing

delta==0 is EMPTY: of 2509 mismatches not one has the original's length, while the neighbouring
buckets hold 70-96 each. Getting a function to the right LENGTH is very nearly equivalent to
getting it byte-clean. Length is the metric to chase.

- **`indirect_call` smell (2019 of 2599 mismatches)** is NOT causal: only 3 functions emit an
  indirect call the original lacks. The smell fires on the IR, not on a defect.
- **`rep movs`/`stos`/`scas` expansion** (we render the loop, the original has the string op) is
  real but small: 109 functions, 4 byte-clean.

## What the aggregate says the difference actually IS

Mnemonic totals over 501 mismatching functions (orig vs cand): `pop` -428, `mov` -382, `push`
-207, `je` -199 against `lea` +267, `and` +266, `jne` +117, `setne` +80, `neg` +73. Total
instructions 26686 -> 25054 (-6%). Register saves are 39% of the deficit and fixing them converts
NOTHING, so the verdict is decided by the other 61%: condition polarity (`je`/`jne`, `jl`/`jge`,
`jbe`), boolean materialization (`setne al ; and eax,0xff` where the original branched), and
instruction selection (`lea` for `add`/`shl`). Those are structurer and codegen-shape questions.

## THE UNDEFINED-LOCAL CLASS — **NOT** ROOT-CAUSED. Five wrong hypotheses, one real fix.

⚠️ Read this before touching the class. 603 emitted TUs declare a local that is never assigned and
none are byte-clean, and I reported a "root cause" FOUR times; each was wrong at the next layer:

| claimed | disproved by |
|---|---|
| a free varnode with no value | a guard on `!written && !input && !constant` never fired |
| a spurious STACK input | a spacebase guard never fired |
| an INDIRECT creation (Ghidra `pop_failkill`) | instrumenting the kept args showed no such flag |
| the `committed` force-mark inventing it | skipping the force-mark changed nothing |
| a DUPLICATE input at a parameter's location | real, and FIXED (see below) — but the local remained |
| `recover_input_params` and printc disagreeing about EDI | `proto.params` has no EDI; they agree |
| `own_params` polluted mid-pipeline | printed it: `[0, 8, c, 4]`, EDI absent |

**THE ANSWER, traced at the POINT OF CHANGE (`MOSURA_TRACEARG=1` on `op_append_input` /
`op_set_all_input`).** EDI is never appended to any call — zero occurrences corpus-wide for that
function. The final input list `build_input_from_trials` commits for the offending call is

    SETALL op=138 <- [ram+0x10010 register+0x0 const+0x10 register+0xc register+0x4 stack+0xfffffff4]

The fifth argument is a recovered **STACK** argument, `stack+0xfffffff4` — not a register at all.
It only RENDERS as the incoming EDI at print time. That is why every register-keyed guard missed
it, and why all the register-oriented hypotheses below were wrong: the trial is a spacebase trial
registered by `guard_calls` once the stack-pointer placeholder resolved that call's offset.

## THE UNDEFINED-LOCAL CLASS: 603 -> 228, and the remainder is a TAIL, not a class

After the callee-save-slot fix (554ac15) and the use-based parameter test (b7a5763):

    603 TUs -> 228 TUs, of which 17 are byte-clean (was 0)
    undefined local passed as a CALL ARGUMENT:  5   (the sub-case that mattered — essentially closed)
    undefined local used elsewhere:           223

Sampling the 223 shows they are heterogeneous, not one more layer:
  * FUN_00010b84 — parameters now recovered correctly (ESI/EDI); the leftover is `code * pcVar1`,
    an indirect-call TARGET, not a parameter.
  * FUN_00012a78 — every register input is DEAD; the leftover `iVar1` is not a register input at
    all (an INDIRECT creation / call-clobber artifact, i.e. Ghidra's `extraout_` family).

So do NOT attack this as a single class again. The parameter-recovery half is done; what is left is
a tail of distinct causes, each small. Ghidra names the `extraout_`/`in_`/`unaff_` family
explicitly, and the survey emitter already has a declaration path keyed on those prefixes — naming
them that way would make the output honest but change no bytes.

## ⭐ SOLVED (diagnosis): THE SPURIOUS ARGUMENT IS A SAVED CALLEE-SAVE REGISTER'S STACK SLOT

Traced end to end, each step dumped rather than assumed:

    SETALL op=138 <- [ … | stack+0xfffffff4/4 <- Copy register+0x1c/4[i] ]

The fifth argument is a stack slot holding a COPY of the function's INCOMING EDI. And EDI's only
appearance in FUN_000100b9's original is the PROLOGUE:

    push ecx ; push esi ; push edi ; push ebp ; …            ← a callee-save, paired with `pop edi`

So the save's stack slot is being registered as an OUTGOING ARGUMENT: `guard_calls` resolves the
call's stack-pointer offset, the slot translates into the callee's parameter area, and the trial
survives because the varnode is genuinely written (by the save) and traces to a genuine input.
Every guard that assumed "unwritten", "free", "register", or "not a parameter" had to fail.

This is EXACTLY what `ActionRestrictLocal` (coreaction.cc:1957) exists to prevent — the second half
iterates the proto's saved registers and calls `markNotMapped` on the storage where each unaffected
value gets saved. **mosura does not port it** (zero matches, established earlier). It was declined
at the time because the premise was unverified; the premise is now verified.

Predicted reach: every function that SAVES a register and then makes a CALL is exposed. 2134
functions have locals and only 78 are byte-clean; 603 carry a declared-but-never-assigned local and
none are byte-clean.

IMPLEMENT `ActionRestrictLocal`'s saved-register loop, and validate with the sampled loop
(`trybatch.py --idxfile`) on the previously-clean set BEFORE a full run.

**The flags, for reference** (do not guess these — four guards were written and
reverted on wrong assumptions about them):

    SETALL op=138 <- [ ram+0x10010/4[]
                     | register+0x0/4[w def=IntAnd]
                     | const+0x10/4[c]
                     | register+0xc/4[i]
                     | register+0x4/4[i]
                     | stack+0xfffffff4/4[w def=Copy] ]

The spurious fifth argument is WRITTEN, by a COPY. It is not an unwritten slot, not a free varnode,
not a register input — so a guard keyed on any of those cannot fire, which is exactly what happened
four times.

A COPY whose output is a stack varnode is the SIGNATURE of the stack-pointer placeholder machinery
(`create_placeholder` hangs a 1-byte LOAD off the call; `RuleLoadVarnode` rewrites LOAD -> COPY of a
fixed stack slot). Check first whether this is a placeholder that outlived
`abort_spacebase_relative` — the width is 4 rather than the placeholder's 1, so it may instead be a
genuine spill the caller made and the callee never reads. Dump the COPY's INPUT to tell those
apart. Do not write a fifth guard before that is settled.

**THE EARLIER VERIFIED FACT**, from an instrument pointed at the thing that PRODUCES the output
(`MOSURA_CALLARGS=1` in printc's Call arm, which prints the rendered op and its argument varnodes):

    CALLARGS func_0x00010010 op=138
      args=[register+0x0/4 w | const+0x10/4 c | register+0xc/4 in | register+0x4/4 in |
            register+0x1c/4 in]

The fifth argument is the incoming EDI, an INPUT varnode, and EDI is not among the function's
recovered parameters. A guard in `build_input_from_trials` that drops exactly that was written
THREE times and never fired — so the trial reaches the argument list through an earlier branch of
that function (the `isUnref` materialization is the candidate, untested) or through some path that
is not `build_input_from_trials` at all. **Establish which, with an instrument at the point of
change, before writing the guard a fourth time.**

**THE METHOD LESSON, which cost more than the class did:** every wrong hypothesis above came from
an instrument pointed at a path I ASSUMED fed the output — including one that was reading a
CALLEE's call op, not the function's own. Point the instrument at the object that produces the
observable, verify it is that object, and only then reason.

## What WAS fixed here (real, ported, green)

603 emitted TUs declare a local that is never assigned; NONE are byte-clean. Instrumented at the
declaration site (`MOSURA_DECL=1` in printc's `name_of`), FUN_000100b9's `xVar1` reports

    DECL xVar1 written=false input=true def=None

It is a function INPUT varnode that `recover_input_params` did NOT return as a parameter. printc
names it like an ordinary local and declares it — an input has no defining op, so no assignment is
ever emitted — and `build_input_from_trials` passes it as the call's fifth argument. The recompiled
call then carries a load or a push the original does not have.

**Ghidra names these `in_<REG>`/`unaff_<REG>`** (`database.cc:2492`), which is why its output never
shows an undeclared-looking local; the survey emitter already has a declaration path keyed on those
prefixes. mosura gives them ordinary `xVarN` names, so they look like locals and hit nothing.

FOUR guards were tried and all missed, because it is none of these: a free varnode (`!written &&
!input && !constant`), a spacebase input, an indirect creation (Ghidra's `pop_failkill`), or a
trial force-marked by the `committed` branch. It is a REGISTER input that is not a parameter.

**AND ONE LAYER DEEPER (measured, not guessed):** dropping a non-parameter input from the argument
list does NOT fix it, because the varnode IS at a parameter's location. mosura creates DUPLICATE
input varnodes for one storage — the `--only` diagnostic prints `register+0x4/4` twice and
`register+0xc/4` twice for FUN_000100b9. One of the pair becomes `param_4`; the other has no
parameter slot, so printc names it `xVar1`, declares it with no assignment, and it is passed as a
fifth argument. A guard keyed on the varnode's LOCATION cannot separate them.

So the fix is not in argument recovery at all: it is that heritage produces two function inputs for
the same register. Find why before touching `build_input_from_trials` again — a location-keyed
guard was written, gated green, and was completely inert.

Two further fixes, worth different things:
  - naming it `in_<reg>` matches Ghidra and makes the declaration honest — no byte effect;
  - NOT passing a non-parameter input as a call argument is the byte fix, and needs
    `build_input_from_trials` to know the function's own recovered parameter set (call
    `recover_input_params` once per function and cache it, not per call site).

## THE EARLIER LEAD: call arguments are OVER-recovered, not dropped (2026-08-12)

Four earlier attempts assumed WAR2's calls lose arguments. Instrumented (`MOSURA_STACKARG=1`), the
opposite is true for the caller-pop class:

    original      mov edx,0x1000 ; mov eax,0x11098 ; call          TWO arguments
    mosura        func_0x00050dd8(0x11098, 0x1000, param_2, param_3, param_1)   FIVE

Arguments 3-5 are the CALLER's own incoming EAX/EDX/EBX, still live at the call because nothing
overwrote them. Ghidra's defence against exactly this is `AncestorRealistic`'s `isInput()`
early-out ("we expect to see active movement into the parameter"). `derive_input_map` BYPASSES it:
when a recovered callee `reads` list exists (`committed`), every matching trial is force-marked
active without any realism test. That force-mark was added for a real reason — the pass-through in
`f(x) { g(x); }` is a genuine argument (the regmodify MVE) — so it cannot simply be deleted.

Note also that arg3 is the caller's EDX going into the callee's EBX slot, which would need a
`mov ebx,edx` the original does not have. Whether that is a second defect (argument ORDER) or a
consequence of the first is NOT yet established — do not assume.

Stack arguments are NOT the problem: 6118 of 7021 stack ranges reach guard_calls with a resolved
offset. The 903 that do not are the first stack pass, before the rule pool folds the placeholder —
the window pipeline.rs's priming pass exists to open, working as designed. Reading only the head of
that log shows the stragglers and looks like total failure.

### Why the saved register becomes a parameter — and why the obvious fix is WRONG

FUN_00050dd8 opens `push ebx ; push ecx ; push ebp ; mov ebp,esp ; sub esp,0x1c ; mov ecx,0x600 ;
mov ebx,eax`. EBX and ECX are saved and IMMEDIATELY overwritten, so they cannot be parameters —
yet mosura recovers four (EAX, EDX, EBX, ECX). The `push` gives the incoming value a descendant,
so `ActionInputPrototype` marks the trial active. Every caller of such a function then passes
spurious arguments.

The obvious fix is to correct the cspec: under `__watcall` EAX/EDX/EBX/ECX are the ARGUMENT
registers and are scratch, but `specs/x86-32-watcom.cspec` lists EBX/ECX/EDX as `<unaffected>` and
`<killedbycall>` holds only EAX. **DO NOT MAKE THAT CHANGE — it was tried and it breaks three
build-time-verified ground-truth MVEs** (`callee_register_return_is_recovered_with_its_argument`,
`custom_convention_body_is_not_eliminated_as_dead`,
`indirect_call_does_not_clobber_loop_variable`). The register return in `value [ebx]` stops being
recovered and a byte parameter loses its width.

The `<unaffected>` default is DELIBERATE architecture, not an oversight: mosura overrides it
PER CALLEE from the callee's own body (`analysis::decompiler::callee_effects`, and the per-call
effect override in `heritage::guard_calls`). The default is the conservative floor and evidence
raises it. A blanket cspec change fights that design. Whatever fixes the saved-register case has to
work inside it — most likely by recognising the save/restore pair, not by redeclaring the
convention.

### ORACLE-GROUNDED: the saved-register defect is WATCALL-ONLY, and the cspec is the root

MVE (x86:LE:64:default:gcc, bytes `5748c7c70006000048893c25000060005fc3` at 0x400517) — save a
PARAMETER register, immediately overwrite it, restore it:

    push rdi ; mov rdi,0x600 ; mov [0x600000],rdi ; pop rdi ; ret

Ghidra (`oracle/capture --c`) and mosura (`--example dump`) BOTH produce, identically:

    void func(void) { xRam0000000000600000 = 0x600; return; }

No parameter. mosura handles this correctly on the SysV path — the defect is NOT universal and
NOT in `ActionInputPrototype`.

**The difference is the cspec.** In SysV the parameter registers (RDI/RSI/RDX/RCX) are
`killedbycall` and never `<unaffected>`. In `specs/x86-32-watcom.cspec` EBX/ECX/EDX are BOTH
`<input>` pentries AND `<unaffected>`. That dual membership keeps a saved register's exit value
observable, so the restore stays live, so the save stays live, so the incoming value has a
descendant and becomes a parameter.

**BUT NO SUBSET OF THE FIX IS FREE** — measured, each against `ground_truth_parity` (25 tests):

| moved to killedbycall | result |
|---|---|
| EBX, ECX, EDX | 3 failures |
| EBX, ECX | 2 failures |
| EBX | 2 failures |
| ECX | 1 failure |

The MVEs are build-time-verified source-to-bytes pairs, so these are real output regressions, not
score movements. `callee_register_return_is_recovered_with_its_argument` loses its `value [ebx]`
register return entirely and a byte parameter loses its width.

So the watcall cspec's `<unaffected>` list is simultaneously (a) the root cause of the
saved-register over-recovery and (b) load-bearing for register-return recovery.

**WHY they depend on it — ANSWERED, and it ends at a named missing capability.** With ECX
killedbycall the narrowest MVE loses a parameter:

    expected  void FUN_08048109(xunknown1 param_1, xunknown4 param_2) { … *pxVar1 = param_1; }
    got       void FUN_08048109(xunknown4 param_1)                    { … *pxVar1 = xVar2;   }

It holds a byte parameter in ECX ACROSS a call. Killedbycall makes the call clobber it, so the
incoming value never reaches the store. The optimistic `<unaffected>` default is the ONLY thing
keeping it alive, because **the per-call effect override in `guard_calls` is ONE-DIRECTIONAL**: it
upgrades `<unaffected>` -> killedbycall when `CallSpec::overwrites` says the callee writes the
register, and has no downgrade for a callee that demonstrably PRESERVES a killedbycall register.

The symmetric half was implemented and MEASURED: cspec corrected (EDX/EBX/ECX killedbycall) plus a
downgrade branch gated on `cs.reads.is_some()` (the marker that `callee_effects` completed, so
`overwrites` is exact rather than a lower bound). Still 3 failures — the downgrade never fires,
because `analysis::decompiler::callee_effects` BAILS AT THE FIRST BRANCH and these MVEs' callees
branch. Reverted; 25/25 green.

**So the chain is: correct watcall cspec -> needs the symmetric override -> needs COMPLETE callee
effects for BRANCHING callees.**

That last capability was BUILT and it WORKS — `callee_writes_cfg`, a BFS over the callee's
reachable body collecting every register write, returning `None` on a nested call / indirect branch
/ budget exhaustion so that "absent from the set" is a sound "never written". On the failing MVE's
callee it returns `Some([512, 523, 12, 519, 518, 514, 644])`: EBX (offset 12) plus flags, and
correctly NOT EAX/ECX/EDX. Wired to a symmetric downgrade in `guard_calls` and combined with the
corrected cspec, `ground_truth_parity` went from 3 wrong-output failures to
**`left: ""` — mosura produces NOTHING**, i.e. the decompile itself now fails.

**RESOLVED — the correction is RIGHT, and the apparent regression was three of my own bugs
(M23-M27, 2026-08-12).**

The `left: ""` was never a crash: the test's `body()` helper skips lines until one starts with
`void FUN_`, so an empty left means the RETURN TYPE changed. Four couplings had to be untangled to
get all 25 MVEs green with the corrected cspec (`callee_writes_cfg`; the symmetric downgrade with
the no-evidence case kept optimistic; never downgrading the RETURN storage; and decoupling
`callee_effects`' write list from the model's unaffected list).

The first measurement came back **385 -> 374** and I reverted it. **That was wrong.** The user's
instruction — *"sometimes a correction might decrease the score, use your judgment, let's avoid
local minimums"* — is the rule here: the cspec is mosura-AUTHORED (Ghidra ships no watcall spec),
so it is OUR claim about the compiler, and Open Watcom's convention plus warcraft2-re's proven
`modify [eax edx ebx ecx]` sources both say the argument registers are scratch. A wrong model that
scores better is a local minimum.

Re-landed, and every one of the 15 "regressions" was a REAL DEFECT the optimistic `<unaffected>`
model had been masking:

| defect | symptom |
|---|---|
| `callee_writes_cfg` counted a `pop` as a WRITE | callee-saved registers looked clobbered; a caller's loop counter was absorbed into the call as an argument and stopped advancing — **an infinite loop in the emitted C** (FUN_000458ec) |
| write-list dedup kept the FIRST width at an address | `mov al` before `mov ax` returned `char`; truncating cast, wrong opcode (FUN_00043898) |
| a SUB-REGISTER write counted as output storage | `mov ah,1` outranked a later `xor eax,eax`, so the return of 0 vanished (FUN_00011ab8) |

All three were unreachable behind the old gate, which kept the return register out of the write
list entirely. Progression: 379 -> 370 (buggy) -> 380 -> 380 -> **382, zero regressions**.

**The lesson, and it is the important one:** a score drop from a correction is a HYPOTHESIS about
your own code, not a verdict on the correction. Read the regressed functions' emitted C before
reverting anything.

### ALSO NAMED: `ActionRestrictLocal` is not ported (zero matches in mosura)

Ghidra `coreaction.cc:1957`. Its second half is precisely the saved-register handling:

```cpp
  eiter = data.getFuncProto().effectBegin();
  for(;eiter!=endeiter;++eiter) {            // Iterate through saved registers
    if ((*eiter).getType() == EffectRecord::killedbycall) continue;   // Not saved
    vn = data.findVarnodeInput((*eiter).getSize(),(*eiter).getAddress());
    if ((vn != (Varnode *)0)&&(vn->isUnaffected())) {
      for(iter=vn->beginDescend();iter!=vn->endDescend();++iter) {
        op = *iter;
        if (op->code() != CPUI_COPY) continue;
        Varnode *outvn = op->getOut();
        if (!data.getScopeLocal()->isUnaffectedStorage(outvn)) continue;
        data.getScopeLocal()->markNotMapped(outvn->getSpace(),outvn->getOffset(),outvn->getSize(),false);
      }
    }
  }
```

Its FIRST half (locked call parameters) is inert here — mosura's call prototypes are never
input-locked, which `build_input_from_trials` and `resolve_spacebase_relative` both already
document.

mosura has the machinery to port it: `decompile/scope.rs` and `decompile/varmap.rs`, and the
`UNAFFECTED` varnode flag (`varnode.rs:34`) and EffectRecord list (`fspec.rs:647`) already exist.

⚠️ **THE PREMISE IS NOT YET VERIFIED.** This action marks the SAVE SLOT as not-mapped, which stops
it becoming a local. Whether that also stops the saved register becoming a PARAMETER — the actual
defect — has NOT been established. Per CLAUDE.md ("New code is ALWAYS a faithful port — never a
hypothesis to test-and-revert. Before writing any code, ground it READ-ONLY until you have verified
the premise"), ground it with the rule-trace diff / oracle IR dump on FUN_00050dd8 BEFORE writing
any of it. It is a missing faithful port and worth adding on those grounds regardless; do not
assume it is the fix for this class.

## ⚠️ THREE INSTRUMENTS WERE FOUND LYING IN ONE CAMPAIGN

1. trybatch scored `cand == orig`, missing compare.py's relocation masking -> both arms of three
   experiments read zero.
2. whydiff compared against the UNTRIMMED original -> invented a divergent region at the end of
   every padded function (82 of them, top of the census).
3. whydiff disassembles the slice at base 0, so call TARGETS in its ORIGINAL column are meaningless.
   Still unfixed. Do not read call targets out of whydiff.

Rule: any probe must reproduce the known baseline before its negative is believed. trybatch does
this now (384 of 385 clean verdicts reproduced).

Related: [[byte-exact-class-map-2026-08-11]], [[prologue-order-is-chain-frame]],
[[caller-evidence-prototypes]].
