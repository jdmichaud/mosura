# Porting Ghidra's `<tracked_set>` — resolve the direction flag (and any tracked register) at entry

## The defect this fixes

mosura diverges from the Ghidra oracle on any `rep`-string op. On a 19-byte `rep movsd` fixture
(`x86_repmovsd`), same bytes, same SLEIGH lift:

```c
// Ghidra (oracle/capture --c)            // mosura (examples/dumpc)
p = p + 1;                                uint1 uVar1;              // DF, never assigned
                                          p = p + (uVar1 * -2 + 1); // DF left symbolic
```

`MOVS` advances its pointers by `+size` when `DF==0` and `-size` when `DF==1`; SLEIGH models this
as `size * (zext(DF)*-2 + 1)`. Ghidra knows `DF==0` and folds the stride to `+1`; mosura reads `DF`
as an uninitialized varnode and prints the `uVar1 * -2 + 1` artifact. This is the direct cause of
the memcpy/rep-string loss measured in `docs/wc2src-wgss-lowsim.md` (the artifact, not the loop).

It is a real **Ghidra-parity divergence**, unflagged because no parity fixture exercised `rep movs`.

## Ghidra's mechanism (verified in the 12.0.3 source)

Every x86 `.pspec` (`x86.pspec`, `x86-64.pspec`, `x86-16.pspec`, …) declares the direction flag as a
**tracked register value** over all of ram:

```xml
<context_data>
  <tracked_set space="ram">
    <set name="DF" val="0"/>
  </tracked_set>
</context_data>
```

`<context_data>` has two halves: `<context_set>` (disassembly context — `longMode`/`addrsize`/…,
which mosura already ports via `lang::pspec_context_sets`) and `<tracked_set>` (decompiler-tracked
register values — **not ported today**; a whole-source grep for `tracked_set` is empty).

The decompiler consumes the tracked set in **`ActionConstbase::apply`** (`coreaction.cc:678`), which
runs **second** in the master action list — `ActionStart` → `ActionConstbase` → … → `ActionHeritage`
(`coreaction.cc:5477-5492`), i.e. before heritage and constant propagation. For each tracked register
it inserts one p-code op at the **start of the entry basic block**:

```cpp
const TrackedSet trackset(data.getArch()->context->getTrackedSet(data.getAddress()));
for (i in trackset) {
  op = data.newOp(1, bb->getStart());
  data.newVarnodeOut(ctx.loc.size, addr, op);     // output = the register (DF)
  vnin = data.newConstant(ctx.loc.size, ctx.val); // input  = the constant (0)
  data.opSetOpcode(op, CPUI_COPY);                 // DF = COPY 0
  data.opInsertBegin(op, bb);
}
```

Heritage SSA-ifies `DF = 0`; constant propagation flows it into `zext(DF)*-2+1`, which folds to `+1`.
The x86 pspec tracks only `DF`, but the mechanism is generic over `(register, value)`.

## The port — four pieces, every primitive already in mosura

1. **Parse `<tracked_set>`** — `lang::pspec_tracked_sets(pspec) -> Vec<(String, u64)>`, a clone of
   `pspec_context_sets` (`lang.rs:178`) filtering the `tracked_set`/`set` tags. + unit test on
   `x86-32-watcom` (expects `[("DF", 0)]`).
2. **Store on the `Spec`** — resolve each name to `(register offset, size)` via
   `Spec::register_offset`/`register_size` (`engine.rs:499/545`) and carry the resolved default set on
   the loaded `Spec` (the same place `laned` lives, `speccache.rs`). One space-wide default is all we
   need — no per-address `ContextDatabase`.
3. **Port `ActionConstbase`** — a new `Action` in `decompile/action.rs`: get the entry block
   (`BlockId(0)`); per tracked register build `new_const(size, val)` (`funcdata.rs:880`) +
   `new_varnode(size, reg_addr)` (`:847`) + a `Copy` op via `new_op` + `op_insert_begin` — the exact
   idiom already at `blockjoin.rs:238-239`. (We port only the tracked-set half; Ghidra's
   `getInjectUponEntry` half is a separate, unneeeded concern here.)
4. **Wire into the pipeline** — insert the action after `ActionStart`, before heritage, in
   `pipeline::decompile_with_restart`.

## Acceptance test (is the acceptance criterion)

Promote the fixture to `oracle/fixtures/x86_repmovsd.xml` and add a decompile test asserting mosura
emits `+ 1` (matching `oracle/capture --c`), not `* -2 + 1`. This is a standing rep-string parity
guard. The one assumption it settles: that mosura's const-prop folds `zext(0)*-2+1 → 1` (a Ghidra
rule mosura ports). If it does not collapse, the gap is in that fold rule, not this port.

## Blast radius & measurement

Inserts `DF = COPY 0` into **every** x86 function — inert and dead-code-removed where DF is unused;
the stride cleanup fires only on rep-string functions (~137 the subject TUs). As a faithful Ghidra-parity
fix it is authoritative and lands regardless of corpus direction.

**Measured (the subject round `tracked` vs zc66, commit `a9d205b`):** WGSS **0.5196 → 0.5234** (+0.00383,
weighted +468.5 insn-sim); **143 functions moved, 125 up / 18 down, 0 verdict flips**; EXACT held at
**828**. As scoped, **byte-exactness does not change** here (a clean `+1` loop still compiles to a
loop) — the rep-string TUs just lose the artifact, so their similarity rises. The byte-exact win is
the separate rep-string→`memcpy` intrinsic emitter arm (layer 2, `docs/wc2src-wgss-lowsim.md`).

## Plan

1. `lang::pspec_tracked_sets` + unit test.
2. Resolve + store the default tracked set on `Spec`.
3. `ActionConstbase` port + wire into the pipeline.
4. `oracle/fixtures/x86_repmovsd.xml` + decompile parity test (`+ 1`, not `* -2 + 1`).
5. `cargo test`; then a subject round, report both numbers.
