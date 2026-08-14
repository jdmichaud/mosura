# Byte-exact — where this stands

*Re-measured from scratch on branch `be2`. Regenerate rather than quote these after any change:
`war2_survey <exe> <out>` then `recompile_check <exe> <out>/manifest.tsv <out>/src recover
<WATCOM> --out <tsv> --divergences <tsv>`.*

## The measurement

**432 of 2948 compilable functions are byte-exact**: the C mosura emits, compiled with Watcom
10.0a and relinked at the original's addresses, reproduces the original's bytes exactly —
relocation sites resolved and *verified to the same targets*, not masked. 3023 functions are
emitted; 75 fail to compile.

| step | EXACT |
| --- | --- |
| baseline, re-measured | 421 |
| callee stack-cleanup recovery (`recompile::convention`) | **432** |
| per-function selection over the `return-width` axis | +2 |

Two instrument defects were fixed first, and the numbers before them are not comparable:

- A `CALL` pushes its return address as a constant, so one byte of upstream size drift made every
  later call report an `immediate` divergence it did not have — 5741 rows across 1722 functions.
- With that constant erased those pairs became `encoding`, the class meaning "not reachable from
  C, do not work on this function". That would have written **122 functions** off the work-list
  for a difference entirely downstream of a fixable one. They are `layout-shift` now, marked
  derived so they can never head a work-list.

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

## Open thread 1a — the 47 functions the pass still breaks

The pass is still net −10 against the default (422 vs 432); the union of on/off is 469. It breaks 47
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
