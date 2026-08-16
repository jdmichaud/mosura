# Byte-exact — where this stands

*Re-measured from scratch on branch `be2`. Regenerate rather than quote these after any change:
`war2_survey <exe> <out>` then `recompile_check <exe> <out>/manifest.tsv <out>/src recover
<WATCOM> --out <tsv> --divergences <tsv>`.*

## The measurement

**539 of 3023 emitted functions are byte-exact** from a single default configuration, and
**557** if the prototype-pass arm is also selected per function (verified by recompiling the
materialized tree, not by joining verdict files).

The default configuration is the one that matters: it is a single decompile pass, so it is
what `war2_survey <exe> <out>` produces with no environment set. The arm requires a second
decompile of every function and a second compile round, and buys 18 functions.

| step (default configuration) | EXACT |
| --- | --- |
| baseline, re-measured | 421 |
| callee stack-cleanup recovery (`recompile::convention`) | 432 |
| recovered callee prototype treated as fact, not candidate | 433 |
| **call arguments the chain rule was discarding** | **514** |
| stack-pointer offset recorded at the CALL op | 536 |
| **range offset canonicalized to its space** | **539** |

| configuration | EXACT |
| --- | --- |
| default, single pass | **564** |
| prototype pass alone (`MOSURA_PROTO_PASS=1`) | 560 |
| both, best-of per function (`recompile_select`) | **591** |

(The default's 539 -> 564 is the function-extent fix -- a measurement correction, recorded in
its own commit. The pass's 501 -> 560 and the union's 557 -> 591 are this thread: the anchored
placeholder (`19d8060`), the locked-with-varargs prototype port (`b6c7d31`), and recovered
per-call extrapop (`d854c22`). The pass is 4 functions behind the default, from 63 behind.)

The prototype pass alone is still 38 behind the default. Against the default it wins 18
functions and loses 56, and those 56 are the work-list below: eliminating them retires the arm
and with it the doubled decompile and compile.

### One address per location

`wrap_offset` existed but was called in exactly three places in the decompiler, so the
invariant "an offset is canonical for its space" held only where someone remembered it. The
same stack slot reached `guard_calls` as both `0xffffffec` and `0xffffffffffffffe8`; two
spellings are two `Address`es, so a trial created under one never matched the varnode under
the other and the argument was dropped at commit. Canonicalizing before the `Address` is
formed (`c38ce6a`) is worth +3 on the default configuration and, more importantly, removes a
whole class of silent mismatch that is not x86-specific -- any space narrower than 64 bits
has it.

### CLOSED: open thread 3 -- the trailing stack trial (60 -> 38 pass losses, `19d8060`)

The dropped trailing stack argument was not a fillin problem. The chain: the prototype pass's
call_specs entries opt calls in to `ActionExtraPopSetup` (which iterates `call_specs.keys()`
where Ghidra walks ALL calls); watcall's unknown extrapop plants an ESP INDIRECT before the
CALL; the stack placeholder, inserted after it, binds the INDIRECT's post-call OUTPUT; the
recorded stack offset comes out one slot high; the real argument translates below the
parameter area and no trial is ever registered. `FUN_00023514` recorded -20 where the truth
is -24, and `PUSH 9` vanished.

Fixed by anchoring the placeholder BEFORE the call's extrapop INDIRECT -- gated to calls whose
RECOVERED prototype names stack storage (Ghidra's own locked-prototype condition,
coreaction.cc:1498). The gate is load-bearing twice over; both arms were measured before the
gate existed:

* ungated, the default configuration lost 2 functions (`FUN_000121e8`, `FUN_000485a0`);
* anchored at register-only callees, `FUN_0001fdbc`'s 63 memset calls grew phantom stack
  arguments from the caller's own save slots (EXACT -> 0.522).

Standing after: pass 544 (from 522), losses vs default 38 (from 60), union 582, default emit
byte-identical.

### Open thread 4 -- phantom stack trials wherever the offset resolves wrong

REFINED (post `b6c7d31`, `MOSURA_SAVEDSLOT=1` on `FUN_000121e8`): the surviving phantom at the
losses examined is the RETURN-ADDRESS slot, not the save slots. A stale return address is a
constant-valued stack write -- `STORE(ESP, next_pc)` converted to a stack COPY of a constant --
and once a mis-resolved stack offset lets it translate into the parameter window it is
INDISTINGUISHABLE from a `PUSH imm` argument: written (realistic), consumed only by the call
(ancestorOpUse accepts). No value-side guard can reject it; only correct GEOMETRY can, by
keeping it at `trans 0`, below the parameter area. The `is_saved_slot` guard behaved correctly
in the instrumented case (`copy_found=false` for a slot no input register is copied into is
the right answer -- it is not a save slot).

The offsets go wrong at calls still on the OLD placeholder geometry (post-call INDIRECT
binding), which is every call whose recovered prototype does not name stack storage. The
endgame is therefore to make the ANCHORED binding unconditional -- one offset convention for
every call, return-address slots excluded by geometry everywhere, save slots vetoed by
`is_saved_slot`'s copy check, and the remaining trials genuinely arguments. The two default-
config losses the unconditional anchor produced when first tried (`FUN_000121e8`,
`FUN_000485a0`) are the test cases to hold: at correct offsets their RA slots leave the
window, and their save slots must be caught by the copy check or by the restore-side
double-use.

### Superseded framing (kept for the record)

The remaining barrier to resolving stack offsets at EVERY call (as Ghidra does): once the
offset is known, the caller's own saved-register slots (`PUSH EDX ; PUSH EBP` prologue saves)
translate into the callee's parameter window and become trials. They survive realism -- the
slot IS written, and the value DOES trace to a real input -- and `is_saved_slot`'s
`own_saved` veto is inert exactly where it is needed, because `callee_writes_cfg` bails on
any function containing calls, and a function with no calls needs no veto. The emitted
symptom is unmistakable: calls grow arguments that are the caller's own saved registers plus
return-address-shaped constants (`func_0x...(.., param_1, 0x1fe19)`).

A robust `own_saved` (prologue/epilogue save-restore pairing that does not require walking
through calls) would close it, and with it the anchor's gate could widen toward Ghidra's
uniform coverage. 38 pass losses and the 2 known default-config hazards are the measured
stake.

### The single-shot ceiling is Ghidra-parity, measured against the oracle

Asked about `FUN_0001fdbc` with the callee present but unanalyzed (raw import, both functions
created), Ghidra emits `FUN_00050480()` -- ZERO arguments on all 63 calls. The default
single-pass keeps 62 of 63. Argument recovery for calls to known functions is, in Ghidra,
fed by the DATABASE (`ActionDefaultParams` copies the callee's prototype); mosura's
whole-program prototype pass is the port of that database, and under it `FUN_0001fdbc` and
`FUN_00023514` are both EXACT. The pass is the faithful configuration; its remaining 38
losses are the work-list.

### Unrelated pre-existing failure

`disasm_pcode_ratchet` fails (`disasm parity regressed: 244 < 254`). It fails identically
with the working tree stashed, and no commit in this line of work touches disassembler code.
It is inherited, not caused here, and wants its own investigation.

The +81 was two coupled defects — see the commit for `force_inactive_chain`'s missing
`IPTR_SPACEBASE` test and the killedbycall-register save slot. Gained 81, lost 0.

Two instrument defects were fixed before any of this, and numbers predating them are not
comparable: a pushed return address made every call downstream of a size change report a false
`immediate` (5741 rows / 1722 functions), and erasing it turned those into `encoding`, the class
meaning "not reachable from C" — which would have written 122 functions off the work-list.

## Open thread 2 — a trial rejected on an early graph is never reconsidered

The next mechanism in the call-argument family, distinct from the two the +81 fix addressed. It is
NOT "the trial was never registered" and NOT "the chain rule killed it".

Specimen `FUN_00015820`, one divergence from exact: the original is
`MOV EDX,0x8f040 ; MOV EAX,0x8f000 ; CALL 0x12f24` and we emit `func_0x00012f24(0x8f000)` — the
second argument is dropped. `MOSURA_ARG_DEBUG=1` shows the whole story:

```
[why] slot=2 verdict=Inactive uses=[Copy@0x15821 Multiequal Call@0x1584e Call@0x15871 Call@0x15881 …]
[why] slot=2 verdict=Active   uses=[Call@0x1584e]
```

Early on the varnode at that slot is the INCOMING EDX — saved at entry by `PUSH EDX`, used all over
the function — and `ancestor_op_use` correctly rejects it, because it is genuinely not used only by
this call. Later it refines to the `MOV EDX,0x8f040` value whose only consumer IS this call, and the
same machinery correctly judges it **Active**. So the analysis reaches the right answer; the answer
just arrives after the verdict is frozen.

Two things freeze it. `build_input_from_trials` ends with `delete_unused_trials` (fspec.cc:5740),
and a pruned trial cannot return because its range is already heritaged so `guard_calls` never
re-offers it. And `Funcdata::reopen_input` flips `active` alone, which is inert —
`check_input_trial_use` skips any trial already `CHECKED` and the container is still fully-checked,
so the second round re-commits the identical decision.

**Measured and rejected: clearing the verdicts on re-open.** Making `reopen_input` clear
CHECKED/DEFNOUSE/ACTIVE/USED and resetting the pass state, with the pruning deferred until after the
second round, is a REGRESSION — and a bad one. On the specimens it does not add the missing argument;
it removes the arguments that were already right, including `FUN_00033370`'s
`func_0x000332c4(param_1, param_2, 0x8ce58)` which the +81 fix had made exact. Clearing a verdict
discards a good committed decision rather than refining it, because the second evaluation runs
against a graph where the earlier evidence is no longer visible either.

**And the narrow version fails too, which rules out the whole family.** Recording on each trial the
varnode its verdict was formed against, then re-evaluating on re-open ONLY the trials whose slot no
longer holds that varnode, is also a regression — worse than the broad version. `FUN_00033370` drops
from `func_0x000332c4(param_1, param_2, 0x8ce58)` to two arguments, and `FUN_00015820` loses EAX as
well as EDX.

The reason is the opposite of the assumption behind both attempts. The LATE verdict is not the
better one. By the time a re-open happens the graph has been transformed — constants folded, values
merged through MULTIEQUALs — and `ancestor_op_use` fails on values it previously accepted. The early
verdict is usually the sound one; it is simply taken while the slot still holds the wrong varnode.

So the fix is not in the re-open mechanism at any granularity. The question is why the slot holds the
incoming EDX at the moment the trial is first judged, instead of the constant the caller stores
immediately before the call — a heritage/ordering question about when `guard_calls`' manufactured
read is linked, not an argument-recovery one.

## The work-list, by measured marginal value

Not "which class is biggest" — which class, if *eliminated*, leaves functions with **no**
divergence at all. That is the number that converts to EXACT. From the per-divergence fact table
(`recompile::report`):

| cause | functions whose ONLY cause it is | cumulative if also eliminated |
| --- | --- | --- |
| `missing`/`extra` (call arguments) | 45 | 477 |
| `save/args` (missing PUSH/POP) | 9 | 554 |
| `immediate`/`operand-form` | 21 | 629 |
| `selection` | 7 | 828 |
| `regalloc` | 3 | 1510 |

The first two are one cause — **we call functions with too few arguments** — and that is open
thread 1. 996 missing `ADD ESP,K` rows across 354 functions are the caller-side of the same thing.

## Open thread 1 — the propagated-prototype argument, RE-DIAGNOSED

Whole-program prototype recovery is built (`analysis::interface`, `Program::recovered_protos`,
bound at every direct call). It is OFF by default (`MOSURA_PROTO_PASS=1`). Measured on WAR2 with
the corrected instrument: `missing` 1157 → 1081, but `extra` 467 → 603 and COMPILE_FAIL 75 → 96,
so EXACT goes 421 → 394. The prototypes are right; the pass loses on spurious arguments.

**Iterating it to a fixpoint was tried and rejected.** Round one's snapshot is taken before any
prototype exists, so it is systematically narrower than what the same callee recovers later —
`FUN_0004c978` gives `[register+0x0/2]` where the function takes `register+0x0/4, register+0x8/4`,
which deletes its caller's second argument. Iterating measured **413** against 422 for one round,
and never converged within four rounds: each extra round reduces `missing` exactly as predicted
and buys more `extra` than it is worth.

**The previously recorded diagnosis was wrong, and it was wrong in a way that sent the fix to the
wrong subsystem.** It read this instrument line

```
[arg] call@0x13c6b slot=1 size=4 unref=FALSE addr=register+0x0 vn=Some((4, written=false, free=false))
```

as "an argument resolved to a varnode that is linked but UNWRITTEN", concluded the argument had no
reaching definition, and built a call re-open mechanism on that premise. But `written=false,
free=false` is exactly what a **constant** varnode reports — a constant is neither written nor
free. The argument had not failed to resolve; it had already been *replaced by* `#0x0:4`. The
instrument now prints the whole input list, which makes the difference impossible to misread:

```
[arg] call@0x13c6b slot=1 ... inputs=[0:ram+0x5a48c/4- 1*const+0x0/4- 2:register+0x8/4w 3:register+0xc/4w]
```

Slot 1 — the slot the trial names, and the correct one — already holds the constant when
`build_input_from_trials` reads it. The slot bookkeeping is fine.

**What actually happens, from the rule trace** (`MOSURA_OPACTION=1`, `FUN_00013c50`). Heritage
binds the argument correctly:

```
0x13c6b:31: CALL r0x5a48c:4(free) u0x10009:1(...) r0x0:4(free)          r0x8:4(free) r0xc:4(free)
   0x13c6b:31: CALL r0x5a48c:4(free) u0x10009:1(...) r0x0:4(0x13c5e:12) r0x8:4(0x13c56:8) r0xc:4(0x13c54:7)
```

`r0x0:4(0x13c5e:12)` is the output of the call five instructions earlier — exactly the value the
original passes by doing nothing at all. Then one action replaces it:

```
DEBUG 1249404: resolvecalls
0x13c6b:31: CALL ... r0x0:4(0x13c5e:12) r0x8:4(...) r0xc:4(...)
   0x13c6b:31: CALL ... #0x0:4          r0x8:4(...) r0xc:4(...)
```

`ActionResolveCalls` is `resolve_return` + `resolve_call_args`. The constant is already in the slot
by the time this call's `build_input_from_trials` runs, so the substitution happens earlier within
that same action — that is the next thing to isolate, and it is a *dataflow* question, not an
action-ordering one.

**Ground truth, from Ghidra with the callee's parameter forced** (`GHIDRA_POSTSCRIPT=
DecompileWithForcedParams.java GHIDRA_POSTSCRIPT_ARGS='5a48c=EAX' scripts/ghidra-decompile-war2.sh
5a48c 596b0 13c50`):

```c
forced_1 = FUN_000596b0();
if (param_2 != *(int *)(forced_1 + 0x14)) { *(int *)(forced_1 + 0x14) = param_2; FUN_0005a48c(forced_1); }
```

Ghidra passes the previous call's result. mosura emits `func_0x0005a48c(0)`, and Watcom then emits
the `XOR EAX,EAX` that shows up as the `extra` divergence. So this is a port defect with a named
oracle answer, not a design difference.

**Fixed, and what it was worth.** `check_input_trial_use` runs before `derive_input_map`, and its
`markNoUse` verdict does not merely mark — it FREES the dataflow, replacing the input slot with a
constant 0 (fspec.cc:5650-5651). `derive_input_map` then re-marks the trial active, which cannot
restore a varnode that is now a constant. A trial at storage the callee's recovered prototype names
is marked Active inside the check now. Measured: pass ON **394 → 422** EXACT, `missing` 1081 → 1019.

The gate has to sit INSIDE the check. Skipping `check_input_trial_use` wholesale also skips the
marking and the pass counter, so the list commits on pass 0 and arguments vanish — measured, the
specimen came back as `func_0x0005a48c()` with no argument at all.

## Open thread 1b — two coupled defects in the argument chain rule

**This is the call-argument family's root defect in the DEFAULT configuration** (no prototype
pass). Both halves are located and oracle-confirmed; they must be fixed together, because fixing
either alone measures worse.

Sized by marginal value on the 433 baseline: **73 functions** have only call-argument-shaped
divergences — missing `PUSH`/`POP` saves, missing `MOV <argreg>,K` setup, missing `PUSH K` stack
arguments, missing `ADD ESP,K` cleanup. Ten are a single divergence from exact, 26 within three.
(2225 merely *exhibit* one of those; that number means nothing.)

Specimen `FUN_00033370`, three instructions:

```
- 00033373  MOV EBX,0x8ce58 |            [missing]
  00033378  CALL 0x332c4    | CALL 0x332c4
```

The callee takes its argument in **EBX** — watcall slot 3 of EAX/EDX/EBX/ECX — and slots 1 and 2
are unused at this site. We emit `func_0x000332c4()`. Ghidra, asked with the callee's parameter
forced, emits `FUN_000332c4(0x8ce58)`.

`MOSURA_ARG_DEBUG=1` (with the `[check]`/`[verdict]`/`[trials]` instruments) traces it precisely:
the evaluation marks EBX **Active**, and `fillin_map` then clears it. Stage-by-stage, the clearing
is in `force_inactive_chain`, and the kill fires at `i=0` with `chainlength=1` — before any chain
could form.

### Half one — the chain condition is mis-ported (mark it, fix it WITH half two)

Ghidra sets `seenchain` from an unref trial **only for a stack location**:

```c
if (trial.isUnref() && active->isRecoverSubcall()) {
    if (trial.getAddress().getSpace()->getType() == IPTR_SPACEBASE)   // stack only
        seenchain = true;
}
```

The reasoning is specific to the stack: an unreferenced *register* may plausibly be an input the
caller passes straight through, whereas a stack slot cannot, since caller and callee stack offsets
differ. Our port dropped the inner test, under a comment asserting the branch was unreachable
because `is_recover_subcall` is false. **It is reachable and it fires.** One synthesized register
hole then sets `seenchain`, and every later trial in the section is marked inactive regardless of
chain length — which is what kills the real EBX argument.

### Half two — hole-filling promotes synthesized trials into real parameters

Restoring the stack-only test alone measures **373 EXACT against 433** — gained 22, lost 82. The
gains are the intended ones. The losses are all `PUSH`/`POP` of `EDX`/`EBX`: with `seenchain` no
longer poisoning the section, `force_inactive_chain`'s tail loop ("fill in holes of inactive
trials") marks the two synthesized unref holes ACTIVE, `fillin_map` marks every active trial used,
and they become real parameters of the CALLER — `FUN_00033370` goes from `void f(void)` to
`void f(xunknown4, xunknown4)`. Those registers are then live across the function and Watcom saves
and restores them.

So the hole-filling needs to distinguish a hole that stands for a real argument from one
synthesized purely to keep slot numbering contiguous. Until it does, half one stays out — reverted,
not lost.

**And the specimen is not caller-side at all.** With the prototype pass ON, `FUN_00033370` still
emits `func_0x000332c4()`, because the propagated prototype for the callee is
`[(register,0,4), (register,8,4)]` — EAX and EDX, not the EBX the caller demonstrably sets. Ghidra's
own unforced recovery of that callee is `void FUN_000332c4(void)` with a `byte *in_EAX` and **no
mention of EBX anywhere in its body**. So neither decompiler sees the callee read the register its
caller writes: EBX must be consumed further down, and recovering it needs argument propagation
across more than one call level. Ghidra only produced `FUN_000332c4(0x8ce58)` because the parameter
was forced.

That reframes the family. Trial recovery cannot produce a one-argument call at slot 3 even in
principle — Ghidra's hole-filling is deliberate, since C has no gaps, so slots 1 and 2 must become
arguments once slot 3 is one. The answer has to come from a correct callee prototype, and for this
specimen that prototype is only correct if EBX is propagated through the callee to its own callees.

### Half two, located: a spurious STACK trial drags the register holes in

The 82 losses have one shape, and it is not the hole-filling being wrong in general. Comparing the
trial set at the call, instrumented with `MOSURA_ARG_DEBUG=1`:

| case | trials at the call |
| --- | --- |
| `FUN_00033370` — fix GAINS it | `EAX hole · EDX hole · EBX real` |
| `FUN_00013160` — fix LOSES it | `EAX real · EDX real · EBX hole · ECX hole · stack+0x4 real` |
| `FUN_0001193c` — fix LOSES it | identical shape |

Where the fix helps, the real argument sits at the HIGHEST slot and the holes below it are genuine
pass-throughs — filling them is correct, because C has no gaps. Where it hurts, a `stack+0x4` trial
at the far end extends `max`, so the tail hole-filling promotes the two register holes into
parameters of the CALLER, and Watcom then saves and restores those registers.

**That stack trial is spurious.** `FUN_00013160` is `PUSH EDX ; PUSH EBP ; MOV EBP,ESP ; … ; CALL`
and pushes nothing as an argument, so the callee's first stack-argument slot maps onto the caller's
**saved EBP**. The mis-ported `seenchain` was accidentally masking it — which is why half one cannot
land alone and why the masking looked like correct behaviour for so long.

So the chain is three layers, not two:

1. `force_inactive_chain` mis-ports Ghidra's stack-only test and kills real register arguments.
2. Fixing that exposes hole-promotion, which is *correct* in itself.
3. Hole-promotion only misfires because a spurious stack trial extends its range — and that trial
   exists because the caller's saved registers are being mapped to the callee's argument slots,
   i.e. a spacebase-offset question, not an argument-recovery one.

Fix (3) first; (1) then lands on its own and (2) needs no change.

**Eliminated: the heritage marking on the manufactured varnode.** `build_input_from_trials`'s
`isUnref` branch calls `set_active_heritage()` on the varnode it manufactures, which Ghidra does
not (`vn = data.newVarnode(sz, addr)` and nothing else). That looked like the mechanism — the
manufactured read joining the next renaming round, linking to whatever the caller had in that
register, and the caller's own input recovery then seeing a used input. It is not: removing it
alongside half one leaves the specimen byte-for-byte unchanged, caller parameters and all. Whatever
promotes those holes to caller inputs happens elsewhere, and that is the next thing to find.

## Open thread 1a — the 47 functions the pass still breaks

The pass is still net −11 against the default (422 vs 433); the union of on/off is 469. It breaks 47
functions that are EXACT with it off, **17 of them by a single divergence**, and those 17 split into
two opposite defects — which is why a single "the pass over-recovers" story never fit:

**Under-recovery (8).** `missing: MOV EDX,0x4921c` at 0x49298, 0x492bc, 0x492e0 … — consecutive
near-identical wrappers, each stepping 0x24, each loading the SAME constant into EDX. The original
passes a second argument and we drop it: the callee's recovered prototype does not include EDX.

**Over-recovery, by WIDTH (5).** `extra: AND EAX,0xff` at 0x15227, 0x15247, 0x15267, 0x15287,
0x15297 — again consecutive near-identical functions. The caller masks the argument to one byte
before the call because the recovered parameter is one byte wide; the original passes the whole
register. `analysis::decompiler` already widens a recovered parameter to its exclusion entry's slot
width (`width.max(p.size)`) precisely for this — so either that lookup is failing for these, or the
narrowing is re-introduced after it.

**Over-recovery, plain (4).** `extra: XOR EDX,EDX` / `XOR EAX,EAX` / `XOR EBX,EBX` /
`MOV EDX,0xfffffffc` — a parameter materialized for a slot the original does not pass.

Both directions being present at once means the recovered prototype is right in kind and wrong in
extent, so the next step is per-slot evidence (which callee reads which storage, at what width),
not a global loosening or tightening.

## Compilable C

71 of 2,893 non-library functions emit C that does not compile, and several of the causes make
OTHER functions compile into the wrong arithmetic. Survey, design principles and phased plan:
[`compilable-c-remediation.md`](compilable-c-remediation.md).

## P3 — which equivalent C source

The source-form evidence base is [`byte-exact-source-forms.md`](byte-exact-source-forms.md): the
catalog of binary-evidence -> C-shape mappings measured against Watcom 10.0a, the one-second
single-function probe loop, the plateau analysis from hand-converging WAR2's largest honestly-
measured function (27 -> 177 of 536 instructions matching), and the design the evidence implies
for an automated P3 search. Working artifacts are preserved in `oracle/war2-convergence/`.

That session also produced a WRONG-CODE defect, filed separately:
[`decompiler-bug-guarded-store-hoisted.md`](decompiler-bug-guarded-store-hoisted.md) — a store
the subject performs only on the taken side of a test is emitted unconditionally, so the
recompiled program writes where the original does not. Two verified specimens; not yet compared
against Ghidra.

## FINDING — local declaration order steers Watcom's register allocator

Measured during the FUN_0006c6f0 hand-convergence (the single-function compile loop, ~1s per
probe). With the C otherwise byte-identical, permuting ONLY the order of the local variable
declarations changes the emitted registers:

| declaration order | exactly-matched instruction rows (of 536) |
| --- | --- |
| decompiler's natural order | 172 |
| same declarations, reversed | 173 |
| hill-climbed permutation (~200 probes) | 183 |

Watcom's allocator breaks ties using symbol order, so the declaration sequence is a live input
to code generation. printc currently emits locals in the decompiler's internal variable-numbering
order -- an artifact of SSA/merge processing that carries no information about the original
source -- which means every function's register assignment is conditioned on an arbitrary
choice.

This qualifies as an EmitChoices axis on all three rules: it is semantics-preserving, it is not
derivable from the IR (the original's declaration order left no trace except through the
allocation itself), and the compiler distinguishes it. Unlike the existing axes it is
high-dimensional (n! orders), so the arm mechanism cannot enumerate it -- but a cheap
deterministic heuristic (declare in FIRST-USE order, which is how humans write and how the
original sources were likely ordered) may capture most of the value, with per-function search as
the refinement. Sizing it corpus-wide: emit with first-use-ordered declarations and diff the
EXACT count.

## How to size a fix before writing it

Every estimate in this document must come from one query: **how many functions would become
divergence-FREE if this cause were eliminated.** Not "how many functions show this symptom" — that
number is meaningless and it is always large.

The register-parameter widening below is the worked example of getting this wrong. Sized by a grep
over our own emitted signatures it looked like 313 functions. Sized correctly it was **9**, and it
delivered 1:

| question | answer |
| --- | --- |
| functions whose signature has a narrow register parameter, and are non-exact | 313 |
| functions with ANY width-shaped divergence (`AND EAX,K`, `CWDE`, `MOVZX`, `MOV DL,AL`) | 1581 |
| functions whose ONLY divergences are width-shaped | **9** |
| measured outcome | +1, −29 |

The 313 assumed the narrow parameter was WHY those functions were non-exact. It was not — they sit
at a median of 21 divergences. A symptom that appears in half the corpus as one row among twenty
converts nobody.

The calibration that shows the method works: `ret-n` marginal value said 13, the fix delivered 11.

The trap is that the marginal-value query needs a divergence CLASS to filter on, and some causes
have none — parameter width shows up as ordinary `missing`/`extra` rows. That is not a licence to
substitute a grep over our own output: build the instruction-shape filter instead. It is one query,
and it is the difference between a 35x over-estimate and a calibrated one.

## Measured and rejected — widening a register parameter to its slot

**Do not redo this.** Declaring a register parameter at the convention's slot width instead of the
width the body reads is net **−28** (432 → 404, gained 1, lost 29). It is recorded here because the
premise checks out and the conclusion still does not.

The premise: WAR2's `FUN_00015224` takes a value in EAX and hands it straight to another function.
Declared `xunknown1 param_1` it compiles with an `AND EAX,0xff` the original does not have. Asked
with the callee's parameter forced, Ghidra declares `undefined4 in_EAX` and passes it untouched —
four bytes, the whole register. So on that specimen the wide declaration is right, and it agrees
with the reference decompiler.

It does not generalise. The 29 functions it breaks diverge on `missing: AND EAX,K`,
`missing: CWDE`, `missing: MOV DL,AL` — their originals genuinely DO narrow the incoming register,
because their parameter really is a byte. Declaring it wide deletes the narrowing.

So the parameter width is the same value-versus-storage duality as the return width, and neither
rule wins everywhere. It is not worth making an emission axis either: the split is 29 to 1, so the
narrow width is simply the better default and the wide one buys a single function.

Note the asymmetry that misled this: Ghidra declares the RETURN at the value's width (`undefined1`)
and renders an unrecovered INPUT register at the storage width (`undefined4`). The second is not a
parameter declaration at all — it is an unnamed local standing for "whatever the caller left here",
which reads well and does not rebuild. Reading it as a claim about parameter width is the mistake.

## Open thread 2 — make the search generative

`recompile_search` selects among arms a human emitted; it proposes none. Every one of the 26
functions gained by per-function selection comes from the arm that is a net loss of 26 globally —
which is the whole argument for the choice vector, and for keeping a losing arm alive instead of
reverting it.

To become a search it needs:

1. the emitter callable **per function under an explicit choice vector**, rather than through
   process-wide environment variables and a whole-corpus emit;
2. more axes — temporary splitting vs merging, expression inlining vs an explicit temporary,
   declaration order, statement order among independent statements, loop form, cast placement,
   integer width and signedness where the IR does not pin them;
3. a policy table mapping an attributed divergence class to the axis worth perturbing **at that
   site**, so the search is directed rather than exhaustive.

## What not to undo

- **Relocations are resolved, never masked.** Masking passes a candidate that calls the wrong
  function. The permissive count (identical only outside relocation sites) is reported separately
  and is currently 0, which is a check on the symbol resolution rather than an assumption about it.
- **`postlink` is gone and should stay gone.** It rewrote `89 ec` out of the compiler's output so
  the bytes would match, making every verdict on a frame function a claim about the patch. It now
  modifies 0 of 2952 objects.
- **Both compile paths must keep agreeing.** The shell battery and the mosura driver scored
  168/2449/335/71 identically at the time they were cross-checked; a divergence means one of them
  is measuring something else.
