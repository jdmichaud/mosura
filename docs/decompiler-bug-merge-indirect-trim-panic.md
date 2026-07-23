# Decompiler bug report → decompiler agent: `trimOpInput` OOB panic on INDIRECT (FIXED)

**Owner: decompiler track (`master`). Status: FIXED** (this commit). Surfaced by the WAR2
recompilation-parity survey (docs/war2-function-status.md): all 117 DECOMPILE_FAIL functions
were the *same* panic, and this fix clears every one of them (re-measured: 1286/1286 functions
decompile, `fail=0`).

## Symptom

Decompiling many WAR2 functions (first: `FUN_00011954`) panicked:

```
index out of bounds: the len is 0 but the index is 0
  panic_bounds_check
  merge::trim_slot
  merge::merge_op
  ActionMergeMarkerTrim::apply
  decompile             (src/decompile/pipeline.rs)
```

The panic site is `Merge::trimOpInput` (`src/decompile/merge.rs`, `f.block(parent).in_edges[slot]`).

## Root cause — a partial port of `Merge::trimOpInput`

The offending op is an **INDIRECT** (not a MULTIEQUAL), sitting in the **entry block**
(`BlockId(0)`, `in_edges == []` — normal for an entry). `merge_op` force-merges an INDIRECT's
slot-0 data input (`max == 1`, merge.cc:726) and, when that input's HighVariable cover
conflicts, calls `trimOpInput(op, 0)`.

Ghidra's `Merge::trimOpInput` (merge.cc:692) **branches on the op**:

```cpp
if (op->code() == CPUI_MULTIEQUAL) {
  BlockBasic *bb = (BlockBasic *)op->getParent()->getIn(slot);  // predecessor block
  pc = bb->getStop();
}
else
  pc = op->getAddr();                                            // the op's OWN address
...
if (op->code() == CPUI_MULTIEQUAL)
  data.opInsertEnd(copyop,(BlockBasic *)op->getParent()->getIn(slot));
else
  data.opInsertBefore(copyop,op);                                // in the op's OWN block
```

mosura had ported **only the MULTIEQUAL branch**: it unconditionally computed the predecessor
as `in_edges[slot]` and inserted the COPY at that predecessor's end. For a MULTIEQUAL that is
correct — input `slot` maps to `in_edges[slot]`. For an INDIRECT the slot-0 input is a *data*
value, not a phi edge, so there is no corresponding in-edge; indexing `in_edges[slot]` on the
entry block (0 in-edges) is out of bounds.

## Fix

Port Ghidra's `else` branch: when the op is not a MULTIEQUAL, place the trim COPY in the op's
own block immediately before it (`opInsertBefore`, at `op->getAddr()`), instead of at a
predecessor's end. `trim_op_input` now branches exactly as Ghidra does.

## Gating

- **Unit test** `merge::tests::trim_op_input_on_indirect_trims_in_own_block` — builds an
  INDIRECT in a 0-in-edge block and asserts `trim_op_input` does not panic and inserts the COPY
  before the op in its own block. (Panics on the pre-fix code.)
- **Ground truth (the real binary):** re-running the WAR2 survey EMIT stage over all 1286
  functions now reports `fail=0` (was 117 panics). Corpus byte-neutral (0.9513/57): no datatest
  fixture exercises an INDIRECT force-trim, which is why the decompiler suite stayed green while
  real Watcom-compiled functions hit it.
