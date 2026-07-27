# `TypeOp::propagateType` — ported vs missing (audit @ Brick 1, 2026-07-27)

Ghidra's type propagation is a per-opcode virtual: `TypeOp::propagateType(alttype, op, invn, outvn,
inslot, outslot)` decides whether, and as what, a data-type crosses one edge of one p-code op.
`ActionInferTypes::propagateTypeEdge` (coreaction.cc:5074) calls it for every edge; the base
`TypeOp::propagateType` (typeop.cc:317) returns null, so an opcode with no override propagates
nothing.

mosura's counterpart is `infertypes::TypeInfer::propagate_type` (one `match` over `OpCode`), whose
`_ => None` arm is the base class. This note records which of Ghidra's overrides are ported and which
are not, so the un-ported ones stay visible instead of hiding behind that arm.

Found while grounding the type-inference-core campaign; **none of these is the cause of the
0x70f4d / partialmerge / stackstring divergences** (those are merge-side — see
`merge_test_adjacent` / `merge_addrtied` in `merge.rs`). Listed as an inventory, not a work order.

## Ported

| Ghidra | typeop.cc | mosura arm |
| --- | --- | --- |
| `TypeOpCopy` | 411 | `Copy` |
| `TypeOpLoad` | 487 | `Load` → `propagate_load_store` |
| `TypeOpStore` | 557 | `Store` → `propagate_load_store` |
| `TypeOpEqual` / `TypeOpNotEqual` | 945 / 1009 | `IntEqual` / `IntNotequal` (via the shared compare arm) |
| `TypeOpIntSless` / `TypeOpIntSlessEqual` | 1033 / 1059 | `IntSless` / `IntSlessequal` |
| `TypeOpIntLess` / `TypeOpIntLessEqual` | 1085 / 1109 | `IntLess` / `IntLessequal` |
| `TypeOpIntAdd` | 1181 | `IntAdd` (pointer arm only — see below) |
| `TypeOpMulti` | 1951 | `Multiequal` |
| `TypeOpIndirect` | 2005 | `Indirect` |
| `TypeOpPtradd` | 2268 | `Ptradd` |
| `TypeOpPtrsub` | 2366 | `Ptrsub` |

`TypeOpCast` has no override in Ghidra (it inherits the base no-op); mosura states that explicitly as
a `Cast => None` arm rather than leaving it to `_`, because it is load-bearing — it is what stops a
type relaying back through a cast the `ActionSetCasts` port inserted.

## Not ported

| Ghidra | typeop.cc | what it propagates | why it can't fire yet |
| --- | --- | --- | --- |
| `TypeOpIntAdd` INT/UINT arm | 1185-1189 | an `int`/`uint` onto slot 1 when `in(1)` is constant | mosura's `IntAdd` arm returns `None` for any non-pointer `alttype`. The only *missing* case with a mosura counterpart. |
| `TypeOpIntXor` | 1422 | enum types, and float sign-manipulation (`floatSignManipulation`) | no enum metatype in mosura's `Datatype`; the float arm is reachable and unported |
| `TypeOpIntAnd` | 1455 | same as `IntXor` | same |
| `TypeOpIntOr` | 1488 | enums only | no enum metatype — unreachable |
| `TypeOpPiece` | 2074 | near/far pointer resize; composite sub-type by byte offset | no `TypePointer` word-size/far model, no composite `getSubType` |
| `TypeOpSubpiece` | 2161 | near/far pointer resize; composite/union truncation | same, plus no union `resolveTruncation` |
| `TypeOpSegment` | 2431 | segmented pointers | segmented address model not ported |
| `TypeOpNew` | 2501 | the allocated type through `CPUI_NEW` | no `CPUI_NEW` in mosura's lifter |

Two further `ActionInferTypes` helpers are also unported and are noted in `infertypes.rs`'s module
doc: `propagateRef` (coreaction.cc:5208 — a pointer's pointee type pushed onto varnodes at the
aliased address) and `propagateSpacebaseRef` (5265). Their absence is why mosura's
`propagation_debug` has three of Ghidra's four call sites: the `ptralias` form (5248) belongs to
`propagateRef`.

The metatype an op advertises locally (`PcodeOp::inputTypeLocal` / `outputTypeLocal`, the seeds for
`buildLocaltypes`) is a *separate* table — mosura's `infertypes::op_meta` — and is not affected by
any of the above.
