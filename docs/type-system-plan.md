# Type system — port plan

A faithful port of Ghidra's data-type subsystem: `TypeFactory` (the type registry),
the `Datatype` hierarchy, and `ActionInferTypes` (type propagation). This is the
TODO's biggest remaining lever, but it is a **large, deeply-interdependent subsystem**
(~7,800 lines across `type.cc`, `typeop.cc`, `cast.cc`, plus the inference action in
`coreaction.cc`). This plan breaks it into faithful, individually-measurable phases.

## Why it matters (and its limits)

mosura is "int-everything" today. The structural comparator (`ccompare`) **erases type
names** (`int`/`uint`/`xunknown4` → `T`), so better type *names* do not move the score.
The score-relevant, *structural* payoffs of types are:

1. **Array/pointer indexing** — `p[i]` vs `*(p + i*sz)`. Only **5 of 62** x86 datatests
   use `[]` (loopcomment, modulo, pointerrel, switchind, varcross), but it is a large
   per-line win on those.
2. **Casts** — `*(uint8 *)(p + 8)`, `(int4)x`. Ghidra emits these where types disagree;
   they add `T *` / `T` tokens the comparator keeps the `*` of. Broad but small.

Crucially, **the array-vs-scalar decision is inference-driven, not mechanical**. divopt
and modulo dereference their pointer params identically, yet Ghidra types modulo's as
`int8 *` (→ `param_1[1]`) and divopt's as `xunknown8` scalar (→ `*(uint8 *)(param_1+8)`)
— divopt's scalar typing is downstream of its 128-bit/SSE multiply modeling confusing
the inference. **A naive "divide offset by element size" heuristic would regress
divopt's committed 0.78.** So array indexing *requires* this subsystem; it cannot be
faked. (See the memory's framing correction: port, don't invent heuristics.)

## Reference architecture (what we're porting)

- **`Datatype`** (`type.hh`/`type.cc`) — the type lattice: `TYPE_VOID`, `TYPE_UNKNOWN`,
  `TYPE_INT`/`TYPE_UINT` (by size), `TYPE_BOOL`, `TYPE_FLOAT`, `TYPE_PTR`
  (`TypePointer` → ptrto + wordsize), `TYPE_ARRAY`, `TYPE_STRUCT`, `TYPE_SPACEBASE`.
  Key ops: `typeOrder` (the lattice meet/refinement order), `getSize`, `getMetatype`,
  `getExactPiece` (sub-type at an offset, for struct/array field access).
- **`TypeFactory`** (`type.cc`) — interns/uniquifies types; `getBase(size,meta)`,
  `getTypePointer(size, ptrto, wordsize)`, `getTypeArray`, `getExactPiece`.
- **`ActionInferTypes::apply`** (`coreaction.cc:5374`) — seed each Varnode's *temp type*
  from its op's `getOutputToken`, then `propagateOneType` (`:5172`) walks the SSA graph
  via `propagateTypeEdge`, refining temp types until a fixed point; finally commit temp
  types to the Varnodes.
- **Per-op propagation** (`typeop.cc`) — each `TypeOpX::propagateType(alttype, op,
  invn, outvn, …)` says how a type on one slot flows to another. The load-bearing ones:
  - `TypeOpLoad`/`TypeOpStore` (`:487`/`:557`) — a LOAD/STORE address gets a *pointer to
    the accessed type*; this is what makes a Varnode a pointer.
  - `TypeOpCopy`, `TypeOpInt*`, `TypeOpPtradd`/`TypeOpPtrsub` — copy/arith/array-index
    flow.
  - `TypeOpEqual`/`NotEqual`, the casts in `cast.cc` (`CastStrategy`).
- **PrintC emission** (`printc.cc`) — given committed types, emits `p[i]` (from PTRADD),
  `s->field` / `s.field` (from PTRSUB into a struct), `*(T *)expr` casts (from
  `CastStrategy::castStandard`), and the declaration block with types.

## mosura's substrate (what's already here)

- Structured IR with `Varnode{space,offset,size}` and `PcodeOp` (`sleigh::pcode`).
- SSA (`decomp::ssa`) with reaching defs / phis / uses.
- `decomp::cprint` builds `Expr` trees; `pointer_params`/`uint_params` are *ad-hoc*
  single-purpose inferences that this subsystem will subsume.
- `decomp::divrecover` already does op-level pattern recognition over SSA — the same
  style the type-edge propagation will use.

## Milestones (each faithful, each measured)

- **T0 — Datatype + TypeFactory core. ✅ DONE** (`decomp::types`). The `Datatype`
  lattice (void, unknown, int/uint by size, bool, float, code, ptr, array, spacebase) +
  `type_order` (Ghidra `Datatype::compare`/`typeOrder` — sub-meta-type then size then
  recursive pointee/element) + `get_exact_piece`. Rust value types, so no interning
  factory — just constructors. Unit-tested against Ghidra's specificity rules. No output
  change (foundation).
- **T1 — temp-type seeding + the propagation skeleton.** Port `ActionInferTypes::apply`
  + `propagateOneType`/`propagateTypeEdge` as a fixed-point over mosura's SSA, with a
  *minimal* set of per-op `propagate` rules (COPY/LOAD/STORE/PTRADD/MULTIEQUAL). Produce
  a `HashMap<Def, Datatype>`. Validate the pointer/array/scalar typing of a handful of
  datatests against Ghidra's declared types (modulo → `int8*`, divopt → scalar — this is
  the regression guard).
- **T2 — array/pointer indexing emission. ⚠️ MEASURED NET-NEGATIVE (prototype, reverted).**
  Added `Expr::Index` + element-size inference + `*(p+k)→p[k/sz]` and ran the corpus:
  modulo 0.46→0.54 (+0.08) but **divopt 0.78→0.59 (−0.18)** → aggregate 0.619→0.612
  (ratchet fails). The other 4 array datatests don't benefit (mosura doesn't decompile
  loopcomment/pointerrel/varcross; switchind isn't a param array). The cause is
  fundamental: faithful pointer inference types divopt's param as the pointer it *is*,
  but Ghidra types it `xunknown8` *scalar* (a quirk of its 128-bit/SSE modeling) and
  prints `*(uint8 *)(param_1+8)`. The similarity comparator therefore **penalises mosura
  for being more correct than Ghidra.** So T2 is only worth it *gated by T1 types that
  reproduce divopt's scalar typing* — which needs the SSE-aware propagation, i.e. most
  of the subsystem. Array indexing is **not** a near-term win.
- **T3 — casts.** Port `CastStrategy::castStandard`; emit `*(T *)(…)` / `(T)x` where the
  required type differs from the actual (PrintC's cast points). Broad small gains.
- **T4 — integer width + signedness.** Replace `uint_params`/int-everything with the
  inferred int1/2/4/8 + uint widths in declarations and the cast logic.
- **T5 — structs/unions** (later) — `getExactPiece` field access → `s->field`. Needed by
  packstructaccess / piecestruct / impliedfield / union datatests.

## Risks / notes

- **Scope.** T0+T1 are substantial scaffolding with no score movement; the first
  measurable win is T2. Budget accordingly — this is a multi-session port, not an
  increment.
- **Regression guard.** The whole point of doing this faithfully (vs a heuristic) is to
  type divopt's param as scalar so it keeps its `*(uint8 *)(…)` form. T1's validation
  against Ghidra's declared types is the gate before T2 emits anything.
- **Interdependence.** Unlike `divrecover` (a self-contained recogniser), type
  propagation needs a critical mass of op rules before it produces useful types — T1
  cannot be trimmed much further than the load-bearing set.
