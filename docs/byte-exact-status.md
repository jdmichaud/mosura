# Byte-exact — where this stands, and the two open threads

*Stamped at `d6e87aa`. Numbers here were measured on the WAR2 corpus with recovered build flags;
regenerate rather than quote them after any decompiler change.*

## The measurement

**447 of 2952 compilable functions are byte-clean**: the C mosura emits, compiled with Watcom
10.0a and relinked at the original's addresses, reproduces the original's bytes exactly —
relocation sites resolved and *verified to the same targets*, not masked.

| step | byte-clean |
| --- | --- |
| before this work | 407 |
| return-type storage width (A/B measured, winner defaulted) | 420 |
| build-config recovery replacing the hand-built flags table | 421 |
| per-function emission selection | **447** |

Denominators that matter: 3023 functions emitted, 2952 compile, and **887 use encodings this
toolchain never emits anywhere across three thousand translation units** — software interrupts,
segment-register moves, 16-bit-prefixed operations, string moves. Those are not reachable from C
with this compiler and are not a decompiler defect.

## The work-list, by measured population

Dominant divergence per function, attributable set only:

| cause | functions | what it means |
| --- | --- | --- |
| `missing` | 1090 | the emitted C computes LESS than the original — **wrong code** |
| `extra` | 476 | it computes more — usually a spurious interface |
| `regalloc` | 371 | same program, different registers — reachable by changing the C |
| `selection` | 317 | a different instruction for the same job |
| `immediate` / `operand-form` | 228 | types, stack layout |
| `encoding` | 13 | same instruction, different bytes — **not reachable from C** |

## Open thread 1 — the call recovery ordering

Whole-program prototype recovery is built and correct (`analysis::interface`,
`Program::recovered_protos`, bound at every direct call, 3023 prototypes in 59s). It is OFF by
default (`MOSURA_PROTO_PASS=1`) because it costs 26 byte-exact functions: `missing` −87, `extra`
+105.

The prototypes are right. The defect is that a propagated argument resolves to a varnode that is
linked but **unwritten** — instrumented with `MOSURA_ARG_DEBUG`:

```
[arg] call@0x13c6b slot=1 size=4 unref=FALSE addr=register+0x0 vn=Some((4, written=false, free=false))
```

`ActionResolveCalls` (arguments) is a mainloop member; `ActionActiveReturn` (call outputs) is in
the fullloop tail (`coreaction.cc:5688`). So a call's arguments commit while the *preceding* call
still has no output, and an argument that should be that call's result has no reaching definition.
Both placements are faithful to Ghidra; Ghidra survives it because a fullloop round that commits
outputs forces another round, while mosura's argument list is already committed and its trial
container cleared.

**The fix is to re-open a call whose argument resolved to an unwritten varnode once outputs
commit — not to move an action**, which would diverge from the reference for a reason the
reference does not have. Verify on `FUN_00013c50` (it should emit `func_0x0005a48c(iVar1)` with no
`XOR EAX,EAX`), then re-enable the pass and re-measure; the target is `missing` −87 *without*
`extra` +105.

### Re-opening is built, and it is NECESSARY BUT NOT SUFFICIENT (`@d0f1ddd`)

The re-open exists now, and it exposed a second, real divergence on the way: Ghidra's
`FuncCallSpecs::clearActiveInput` (fspec.hh:1696) flips `isinputactive` and **keeps the trials**,
while mosura DELETED the whole `ParamActive` on commit. Re-opening was therefore impossible by
construction. `ParamActive::active` now models Ghidra's flag, the trials survive, and
`Funcdata::reopen_input` re-opens a call once — bounded, so it cannot cycle — when
`resolve_call_output` commits an output.

**It fires and it does not fix the specimen.** With `MOSURA_ARG_DEBUG` on `FUN_00013c50`, the call
at `0x13c6b` now commits its argument THREE times instead of once, and every commit reports the
same thing:

```
[arg] call@0x13c6b slot=1 size=4 unref=false addr=register+0x0 vn=Some((4, false, false))
```

still `written=false`. Measured on WAR2 with `MOSURA_PROTO_PASS=1`: **395 EXACT / 77 SAME_SHAPE /
2480 MISMATCH / 71 COMPILE_FAIL**, against **421 / 85 / 2447 / 70** with the pass off — the same
−26 byte-exact the pass always cost. The default configuration is unchanged, so the repair is free
but not yet a win.

**Why re-deriving is not enough, and what the remaining half is.**
`build_input_from_trials` resolves an argument by reading `op(call).input(slot)` — the varnode
ALREADY in the slot. Re-opening re-runs that derivation, which re-reads the SAME stale, unwritten
varnode; committing the preceding call's output does not re-link it. Ghidra does not need a re-link
because the read it resolves to is the INDIRECT creation `guardCalls` made, which
`buildOutputFromTrials` then PROMOTES to be the call's output — the reader already points at the
right object. So the remaining work is on the OUTPUT side: either the committed output must adopt
the existing creation varnode that later reads are linked to, or the argument must be resolved by
ADDRESS against current SSA rather than by reusing the slot's varnode. That is the next step, and
it is a heritage/linking question, not an action-ordering one.

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
