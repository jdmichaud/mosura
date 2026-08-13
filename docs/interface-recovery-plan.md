# Interface recovery — the largest attributable class

*Why the emitted C computes less than the original, and what has to exist for it not to.*

## The measurement

Over the WAR2 corpus, with foreign-toolchain functions excluded, the dominant divergence in
**779** attributable functions is `missing`: an instruction the original has and the recompiled
candidate does not. That is not a cosmetic gap. A missing instruction means the emitted C is a
description of a *different program*, and it would be worth fixing even if byte-exactness were
abandoned.

Three sub-classes are confirmed by inspection, and all three are the same problem wearing
different clothes — a function's interface recovered from the function alone.

### 1. Return storage width — *fixed*

The original ends `SETZ AL ; AND EAX,0xff`; the recovered type was `bool`, and a `bool` return
tells the compiler to leave a byte. The declared width is what makes the compiler emit or omit
the widening.

### 2. Arguments the call site drops

`FUN_000190bc` pushes a constant before calling `FUN_0004245c` and the push vanishes. The
reason is visible in the emitted C:

```c
extern int func_0x0004245c();                       /* in the caller  — no prototype at all */
void FUN_0004245c(int4, xunknown2, xunknown2, int4, code *)   /* in the callee — five parameters */
```

The callee's own recovery found five parameters — four in registers, the fifth on the stack. The
caller declares nothing, independently guesses four, and drops the fifth. **The information
exists and never crosses the function boundary.**

### 3. Registers used in and out against the convention

A function whose real contract returns in EBX is decompiled against a model that calls EBX
`<unaffected>`; the write is dead at `ret`, dead code removes it, and the emitted C does less
than the original. The same on the input side produces `void FUN_x(void) { return; }` for a
function with a body.

## Why per-function recovery cannot close this

Each function is decompiled in isolation against the default convention, so every question about
a *neighbour* is answered by a default. That is Ghidra's design too, and asking Ghidra through
its whole-image wrapper produces the same truncated callees — this is not a porting gap.

mosura already carries a partial extension: per call site it scans the callee's body for
registers it overwrites (`CallSpec::overwrites`) and reads before writing (`CallSpec::reads`).
The scan is straight-line — it stops at the first branch or call — which is why it "reaches only
straight-line bodies and barely dents the population". The mechanism is right and its evidence
source is too weak.

## The design

The strong evidence is already computed and then thrown away: decompiling a function *recovers
its prototype*. So recover them all, then decompile again knowing them.

```
pass 1   for each function: decompile, record (params, return storage/type) -> prototype DB
pass 2   for each function: decompile again, binding each direct call to its callee's
         recovered prototype instead of recovering arguments from the call site
```

Two properties make this practical here:

- The corpus emits in 90 seconds, so a second pass is minutes, not hours.
- The dependency is a call graph, not an ordering constraint: pass 2 reads a frozen snapshot from
  pass 1, so there is no fixpoint to diverge. Iterating further (pass 3 from pass 2's DB) is a
  refinement to *measure*, not an assumption to build in.

### Where it plugs in

- The DB is a `Program`-level map from entry address to `FuncProto` — the same structure
  `recover_input_params` already produces per function.
- `record_callee_effects` already runs per call site with whole-program access; the prototype
  binding belongs beside it.
- At a call with a known callee prototype, argument recovery is *replaced*, not merely informed —
  Ghidra's equivalent is an input-locked `FuncCallSpecs`. A recovered-from-the-callee list is
  strictly better evidence than trials taken from one call site, and mixing the two would
  reintroduce the guesses this exists to remove.

### What must be measured, not assumed

- **Does a second pass help or hurt?** A wrong prototype propagates to every caller, so this can
  make things worse in a way per-function recovery cannot. The census is the check, and the
  `missing`/`extra` split is the specific thing to watch: trading `missing` for `extra` is not
  progress.
- **Recursion and indirect calls** have no callee to consult; they must fall back to today's
  behaviour rather than to an empty prototype.
- **Does a third pass move anything?** If not, one round is the answer and the fixpoint machinery
  is not needed.
