# WAR2 type-inference campaign — checkpoint (owner: war2-typeinfer)

Warm-resume anchor for task board #1 (eliminate the 137 WAR2 COMPILE_FAILs by porting Ghidra's
type-inference / cast machinery faithfully). Read this + AGENT.md + CLAUDE.md before writing code.

## Baseline (grounding @ `04d0165`)

The 137 COMPILE_FAILs (Stage 2 re-measure `ad50898`, decompiler byte-neutral to HEAD `04d0165` —
verified `git diff --stat b4ac8f4..HEAD -- crates/mosura/src` is empty). All upstream
type-inference/CAST gaps. Authoritative per-class breakdown (docs/war2-function-status.md appendix):

| Error | Count | Shape | Class | Verdict |
|---|---|---|---|---|
| E1052 void type | 34 | `iVar = (*(code *)p)();` | honest ceiling | **Ghidra emits the same** — not reachable |
| E1079 must be integral | 33 | `uVar4 = pVar2 & -4;` | pointer in bitwise | **Brick 1** (cast inserted) |
| E1029 pointer-to | 17 | `**param_4 = x;` | under-pointered deref | LOAD/STORE cast — later brick |
| E1010 type mismatch | 14 | mixed ptr/int assign | output/assign cast | later brick |
| E1080 must be arithmetic | 12 | `uVar6 = -param_4;` | arith on pointer | **Brick 1** (cast inserted) |
| E1045 subscript non-array | 11 | `xVar1[-1] = ...` | PTRADD-typed scalar | array typing — later brick |
| E1081/E1036/raw/other | 16 | — | mixed | E1036 (pointer subtract) in Brick 1 |

## Method proven (instrument-first, class-A GENERAL per task #4)

WAR2 is DOS/4GW LE — Ghidra loads only the MZ stub, so it can't decompile WAR2 functions
directly. Grounding uses a **gcc-x86-64 reproducer** (`scratchpad/repro/gtype.c`, shapes
`deref_and_mask` / `indirect_use` / `neg_ptr`) decompiled by BOTH mosura (`gt_recompile_probe`,
`analyze_file`) and full-analysis Ghidra (`analyzeHeadless` +
`scratchpad/repro/gs/DecompileDump.java`) on the identical binary. System V so both tools recover
prototypes identically → clean mechanism diff. The type-inference/cast mechanism is
compiler-independent (verified), so fixes land in the GENERAL path (not scoped to Watcom).

- analyzeHeadless: `/data/tools/ghidra_12.0.3_PUBLIC/build/dist/ghidra_12.0.3_DEV/support/analyzeHeadless`
- oracle/capture (isolated libdecomp, corpus fixtures): `oracle/capture <ghidra-src> <fixture.xml> --c`
- Watcom (WAR2's toolchain, for the faithful regression + differential): `/home/jd/tools/open-watcom/binl`

## LANDED

### Brick 1 — pointer/float fed to an integral op is cast (`get_input_cast` base default)
- **Change**: `printc.rs::get_input_cast` fell through to `None` for the generic arithmetic/logical
  ops. Ported Ghidra's base `TypeOp::getInputCast` (typeop.cc): `castStandard(inputTypeLocal, cur,
  false, true)` — `care_ptr_uint=true` casts a same-width pointer to the required integral type.
  Ops: `IntAnd|IntOr|IntXor|IntNegate` (reqtype uint) and `IntSub|IntMult|Int2comp` (reqtype int).
  Metatypes verified from the `TypeOpBinary`/`TypeOpUnary` constructors. These ops do NOT override
  getInputCast in typeop.hh, so they inherit the base default. Transparent for the int/uint/undefined
  primitive lattice (no corpus churn); casts pointer/float operands as Ghidra does.
- **Grounding**: Ghidra `(uint)param_1 & 0xf`, `*p - (long)param_1`; mosura pre-fix `param_1 & 0xfU`,
  `*p - param_1`; post-fix matches (modulo x86-64 8-byte `(uint8)` vs Ghidra's `(uint)`+`(ulong)`
  subpiece — WAR2 32-bit pointers render `(uint)` cleanly).
- **Corpus**: 0.9513 → 0.9516; only `impliedfield` moved (0.938 → 0.954, toward-oracle: mosura now
  emits `(int4)fVar1 * param_1`, the float→int cast Ghidra also emits). 59 byte-identical, zero
  regressions. Suite 559/0, clippy 0.
- **Regression**: `printc.rs::tests::pointer_in_integral_op_is_cast` (fails pre-fix, passes post-fix).
  Docs: `docs/decompiler-bug-ptr-in-integral-op-cast.md`.
- **WAR2 re-measure (clean-vs-clean)**: COMPILE_FAIL **139 → 112 (−27)**. E1079 33→11, E1080 12→5,
  E1036 3→0. ≈32 functions lose the pointer-in-op error; 27 compile fully (→MISMATCH), a few expose a
  secondary type error (E1010/E1045) behind the fixed one. Zero regressions. Original "137" baseline
  had minor stale-obj undercounting; the clean pre-fix baseline measured identically is 139.
  Methodology note: `compile.sh` does NOT clean `obj/` — always `rm -f obj/*.OBJ` before recompiling
  or stale objects hide new failures (contaminated first post-fix run read 88; clean read 112).
  Results saved: `war2-survey/results.prefix.tsv`, `results.postfix.tsv`.
- **Status**: GATE REQUESTED from main (toward-oracle corpus, not byte-identical). Awaiting approval
  to commit.

## NEXT BRICKS (ordered)
1. **Brick 2 (IntAdd/IntLeft) — GROUNDED, HELD (entangled).** Adding these to the base-default set is
   FAITHFUL (Ghidra's exact base getInputCast; proven: `stackstring` moves to EXACTLY Ghidra's
   `func_0x00101000((int8)&xStack_20 + 4)` — toward-oracle). BUT it is entangled with mosura's
   incomplete PTRADD→array-index restructure: `partialsplit` keeps a raw `*(T*)(axStack_58 + i*2)`
   where Ghidra restructures to `auStack_58[i]`, so the new `(int8)axStack_58` cast fires on an
   INT_ADD Ghidra doesn't have (moves that fixture −0.003 away from oracle). Net corpus −0.0001 (flat:
   stackstring +0.014, revisit −0.019 [the `(int2)` matches Ghidra; the dip is a pre-existing
   uRam-vs-iRam double-cast], partialsplit −0.003). HELD pending an array-index/PTRADD restructure
   brick — the faithful cast composes cleanly only once `ptr + i*sz` address computations become
   PTRADD/array-index (AGENT.md rule 2: land the producer before its consumer). Revisit after E1029.
2. **E1029 (17) — GROUNDED, DEEP (needs the directional-type foundation).** Ghidra casts the loaded
   pointer `*(T*)*p`; mosura renders bare `**param_1`. ROOT CAUSE (confirmed by IR probe + the render):
   mosura types the inner load result as a POINTER (correct def-facing propagation — the address of a
   LOAD is pointer-to-loaded-type, which Ghidra does too), so `render_mem`'s `addr_is_ptr` sees a
   pointer and skips the cast. Ghidra ALSO has that def-facing pointer type BUT additionally keeps the
   READ-facing SCALAR type (the value is the pointee of `param_1: undefined8 *`, i.e. `undefined8`),
   and `TypeOpLoad::getInputCast` inserts the cast to reconcile read-facing(scalar) vs the pointer the
   deref needs. **mosura has NO directional type model** — `Varnode::ty` is a single `Option<Datatype>`
   (printc.rs:209 `type_of`), no `getHighTypeReadFacing`/`getHighTypeDefFacing`. So E1029 is not a
   render patch; it needs the read-facing/def-facing distinction (a C-cluster foundation piece), or a
   careful reconstruction of read-facing at the load-address site (mis-fire risk on genuine `int **pp`
   where the inner IS a pointer). Do NOT slap a render heuristic. Original grounding kept below:
   (`scratchpad/repro/e1029.c`,
   `**p` double-deref): Ghidra casts the loaded pointer operand — `return *(undefined8 *)*in_RDI;`,
   `*(undefined8 *)*param_1 = param_2;` — while mosura emits bare `**param_1` (E1029). mosura's printc
   already renders `*(T *)(addr)` for a top-level LOAD/STORE (printc.rs ~687), but the cast does not
   fire when the pointer operand is itself a load result typed as a scalar. Port the LOAD/STORE
   getInputCast override (pointer-to-loaded-type) at that render site.
   MECHANISM (typeop.cc): `TypeOpLoad::getInputCast(op, slot=1)` — reqtype = output type
   (`getHighTypeDefFacing`); if the pointer operand's type is NOT `TYPE_PTR`, return
   `getTypePointer(size, reqtype, wordsize)` → render `*(reqtype *)operand`. If it IS a pointer whose
   ptrTo primitive differs but is same-size, POSTPONE the cast to the output (return null) unless the
   operand is a bad CAST — a subtlety to port carefully. `TypeOpStore::getInputCast(op, slot=1)` is
   symmetric on the value type. This is more involved than Brick 1 (needs the LOAD/STORE out/value
   type + the postpone-to-output branch), so treat as its own staged brick.
3. **E1010 (14)** — mixed pointer/integer assignment. This is an OUTPUT/store cast, not an input cast
   — different mechanism (ActionSetCasts output side / the assignment renderer). Ground first.
4. **E1045 (11)** — PTRADD-derived scalar subscripted. Array/pointer typing (TypeOpPtradd). Deeper.

## FRONTIER ASSESSMENT (post-Brick-1)

Clean COMPILE_FAIL 112. Minus E1052 ceiling (~35) → **~77 actionable**. But the remaining classes
increasingly converge on ONE deep foundation — mosura's type-inference / type model (the "C-cluster",
no persistent HighVariable, no directional read-facing/def-facing types):

| Class | Count | Depth | Foundation needed |
|---|---|---|---|
| E1079/E1080/E1036 | (fixed) | shallow | ✅ Brick 1 (getInputCast base) |
| E1029 under-pointered deref | 17 | DEEP | directional read-facing/def-facing types |
| E1045 subscript non-array | 12 | DEEP | PTRADD→array-index inference (same as held Brick 2) |
| E1010 type mismatch | 16 | MED-DEEP | output/assignment cast + often secondary to E1052 (indirect_call smell) |
| E1081 scalar-type | 6 | ? | ground next |
| E1018 label-undefined | 4 | unrelated | not a type issue (structurer/goto) |

**Assessment:** Brick 1 exhausted the *shallow* input-cast lever (the ops that only needed the base
getInputCast). The next real gains (E1029/E1045/Brick 2) all require the **type-inference foundation**:
(a) directional read-facing/def-facing types (E1029), (b) PTRADD→array-index inference (E1045 + Brick 2
partialsplit + IntAdd composition). These are a multi-brick foundation campaign, not quick wins — and
the memory's standing guidance ([[bounded-levers-exhausted]], [[adaptations-inventory]]) flags the
C-cluster as exactly this deep foundation. The user's mandate ("everything must be implemented so WAR2
compiles byte-exact") points at funding this foundation. RECOMMENDATION: the highest-leverage next
campaign is the **PTRADD→array-index inference** (unblocks E1045 + Brick 2/IntAdd + partialsplit
together — one foundation, three payoffs), then the **directional-type model** (E1029). Ground each as
its own staged brick, differential-first, before coding. Do NOT slap render heuristics.

## OPEN QUESTIONS / CEILINGS
- **E1052 (~35) = honest ceiling — DOCUMENTED verified-faithful**
  (`docs/decompiler-nonbug-e1052-void-indirect-call-faithful.md`). Full-analysis Ghidra emits the
  identical `iVar = (*(code*)p)();` and that construct fails to compile under gcc too (`void value not
  ignored`, wcc386 E1052 class). Recovering the callee return type needs deep prototype analysis;
  mosura already matches Ghidra. NOT decompiler-reachable via faithful porting. **Reclassified OUT of
  the actionable set → true remaining actionable COMPILE_FAIL after Brick 1 = 112 − 35 = 77.**
- Whether some of the "later brick" classes (E1029/E1010/E1045) are also partly ceilings — check each
  against the reproducer + Ghidra before coding.
