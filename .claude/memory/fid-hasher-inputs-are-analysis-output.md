---
name: fid-hasher-inputs-are-analysis-output
description: "⭐ FID's isAddress and isCall are ANALYSIS output (primary reference / flow override), not decode — reading them off SLEIGH silently corrupts every hash"
metadata: 
  node_type: memory
  type: project
  originSessionId: 6a216fa6-e69f-4b20-b0bf-429f1307092c
  modified: 2026-08-07T14:58:01.800Z
---

**⭐ THE STAGE-3 FINDING (2026-08-07, `425818a`): two inputs to Ghidra's FID hasher look like
properties of the INSTRUCTION but are properties of the ANALYSIS.** Both were ported the
plausible way (straight off SLEIGH) and both were wrong; only byte-comparison against Ghidra
could show it. This is [[reftype-is-post-override-not-the-instruction]] striking twice.

1. **`OperandType.ADDRESS`** — `InstructionDB.getOperandType` (`:398-419`) takes the prototype's
   `getOpType` and then **ORs `ADDRESS` in from `getPrimaryReference(opIndex)`** (stack ref,
   external ref, or any ref whose target `isMemoryAddress`). So `LEA RAX,[0x402fe0]` reports
   `isScalar && isAddress`, and the hasher **SUPPRESSES the value** (`MessageDigestFidHasher
   :151-154`) instead of folding it into the specific hash — by design: where a global sits must
   not change a function's signature. Off SLEIGH alone we folded every one in.
2. **`getFlowType().isCall()`** — `InstructionDB.getFlowType` (`:321`) is
   `getModifiedFlowType(proto.getFlowType(this), flowOverride)`. A tail `jmp` an analyzer turned
   into a call **IS** a call, and is subtracted from `codeUnitSize`. From p-code alone the size
   sat one too high on every tail call. mosura already had `flowtype::overridden_flow_props`,
   whose own doc names this class.

**Diagnostic shape that made both findings fast:** when only `codeUnitSize` differs and BOTH
hashes match ⇒ it is `callCount`, not the digest. When only the specific hash + `add` size
differ and the FULL hash matches ⇒ it is `specificCount` gating, i.e. the isScalar/isAddress
branch. The full hash is value-blind by construction, so it partitions the failure space.

**Stage-0 residuals, adjudicated by evidence:**
- **#1 (branch/call target surfaces as `Scalar` not `Address`) = HARMLESS, confirmed.** Ghidra's
  `Address` arm and our `Scalar` arm with `|val| ≥ 256` do *identical* arithmetic and neither
  increments `specificCount`.
- **#3 (empty-operand-mask fallback) = A REAL BUG, and it is the ENTIRE AArch64/m68k gap.** For
  `mov x29,sp` Ghidra gives `sp` an **all-zero** operand value mask → instruction mask
  `e0ffffff`; mosura gives a non-empty mask → `00fcffff`. Fix belongs in `sleigh/engine.rs`'s
  `mainSubGroups` fallback (**sleigh lane**). Plan §8 R7.

**Open (R8):** mosura's references store `op_index = -1`, so `getPrimaryReference(opIndex)`
can't be asked; `tests/fid_hash_parity.rs` reconstructs the operand BY VALUE (the operand whose
scalar equals the ref target). Exact for whole-scalar operands — the only ones whose ADDRESS bit
reaches a hash — but reconstructed, not faithful.

**Numbers @ `425818a`:** 216/292 quads byte-identical; `gcc-x86-64` **52/52** and
`watcom-x86-32` 83/84 (both held hard), `gcc-riscv64` 53/58, `gcc-aarch64` 16/56, `gcc-m68k`
12/41 (ratcheted floors — may rise, never fall). Oracle = `scripts/capture-fid-hashes.sh` →
`oracle/fid/hashes/*.fidhash`, which record each function's BODY RANGES so the gate measures the
hasher and not function-boundary recovery. ⚠️ the run takes ~200s — not a T1 gate.
