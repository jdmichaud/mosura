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

**array-index first brick — MECHANISM VERIFIED (partialsplit IR + oracle, definitive).** The array
access at 0x100041 is `PTRSUB(RSP,-0x58)` (stack-array base) → `INT_ADD(base, index*2)` → `LOAD`.
Ghidra renders `auStack_58[i]`. THE MECHANISM (named, verified):
- Ghidra's FINAL IR (`oracle/capture <g> <fx> --ir -`, NOT the default which breaks at `heritage` and
  is pre-type-inference — that earlier "zero PTRADD" reading was a WRONG-STAGE artifact) has the LOAD
  address as a **PTRADD**: `u0x00009500 = u0x10000063 + RAX(*#0x2)` — printRaw notation: `->` is
  PTRSUB, `+ X(*#0xN)` is PTRADD with element size N. So Ghidra DID form a PTRADD.
- printc `checkArrayDeref` (printc.cc:353) returns true iff the LOAD/STORE pointer operand's def is
  **PTRSUB or PTRADD** → `opLoad` sets `print_load_value` → renders `arr[i]`.
- The PTRADD is formed by **`RulePtrArith`** (ruleaction.cc, group "ptrarith") via its **`AddTreeState`**
  address-tree analyzer: fires on an INT_ADD with a pointer-typed operand (`getTypeReadFacing`), after
  `hasTypeRecoveryStarted`, rewriting `ptr + index*elemsize` → `PTRADD(ptr, index, elemsize)`.

**mosura ALREADY has RulePtrArith + AddTreeState + RulePushPtr ported** (`ptrarith.rs`, 747 lines). So
the brick is NOT a new port. **ROOT CAUSE TRACED (instrumented RulePtrArith::apply_op + AddTreeState::
apply on partialsplit, 2026-07-24):** RulePtrArith DOES fire on the array-index INT_ADD (op 298, pc
0x100041) — it finds the pointer slot, passes evaluate_pointer_expression + verify_preferred_pointer —
but **`AddTreeState::apply` bails at `calc_subtype`: `base_type=Unknown(8), nonmult=1, multiple=0`**.
The chain:
1. The stack-array base is `PTRSUB(RSP, -0x58)`; its `type_read_facing` pointee is **`Unknown(8)`**
   (an 8-byte scalar slot) — NOT the 2-byte access element. So `AddTreeState::new` sets `size=8`
   (ptrarith.rs:318-323, `base_type = ct.ptr_to()`).
2. The index `RAX*2` is a multiple of 2, NOT of 8, so it lands in `nonmult` (not `multiple`).
3. `calc_subtype` (ptrarith.rs:606) — base_type is a plain Unknown (not Struct/Array/Spacebase) with a
   non-empty `nonmult` → `valid=false`. No PTRADD forms → render_mem emits `*(T*)(base + i*2)`.

Ghidra forms the PTRADD with element size 2 (`+ RAX(*#0x2)`) because Ghidra types that stack local's
pointee to MATCH the access. **FULL ROOT CAUSE TRACED (task #5, 2026-07-24 — the complete chain, every
layer instrumented):**

mosura recovers the stack local as `xunknown8 axStack_58[2]` (element size 8); Ghidra recovers
`uint2 auStack_58[10]` (element size 2). The element-size divergence flows all the way down:
1. **varmap `gather_open`** (varmap.rs:448) collects TWO Open hints at -0x58 (confirmed by instrumenting
   `recover_scope`): `size=8 Unknown(8) hi=-1` (from the call `func_0x00101000(auStack_58,...)` — the
   base passed as an untyped pointer whose pointee mosura defaults to `Unknown(8)`) AND `size=2
   Unknown(2) hi=3` (the indexed 2-byte LOAD access). Ghidra's `MapState::gatherOpen` (varmap.cc) uses
   the SAME `base->getType()` pointee mechanism — mosura's port is faithful there.
2. **`restructure` → `merge` → `preferred`** (varmap.rs:561/merge/151): `compare` sorts the size-2 hint
   first (smaller size), so cur=size2, next=size8; they intersect at -0x58 → `merge`. `preferred(size2,
   size8)` falls to the type tiebreak `type_order(Unknown(2), Unknown(8))`.
3. **`type_order`** (types.rs:193): same submeta (both Unknown), so `b.size().cmp(&a.size())` — **"bigger
   size orders first"** → `type_order(Unknown(2), Unknown(8)) = Greater` → `preferred` returns false →
   res_type=1 → **the size-8 hint WINS** → `xunknown8[2]`.

So the divergence is: mosura's `size=8 Unknown(8)` hint (from the untyped call-arg pointer's DEFAULT
8-byte pointee) beats the `size=2` indexed array in the `type_order` tiebreak.

**DECISIVELY NARROWED (Ghidra source verified) → candidate (a), NOT (b):**
- Ghidra's `RangeHint::preferred` (varmap.cc) is mosura's EXACT port — both end at `type->typeOrder(*b->
  type) < 0`; `highind` does NOT participate. Candidate (b) RULED OUT.
- Ghidra's `Datatype::compare` (type.cc) for same submeta returns `op.size - size`, so
  `Unknown(8).typeOrder(Unknown(2)) < 0` — bigger-Unknown wins, IDENTICAL to mosura's `type_order`
  (`b.size().cmp(&a.size())`). mosura's type_order/preferred are FAITHFUL — do NOT touch them.
- Therefore, with BOTH hints present Ghidra would ALSO pick size-8. Since Ghidra's result is element-2,
  **Ghidra does NOT generate the size-8 hint at all.** → **candidate (a) confirmed by necessity.**

**⚠️ SUPERSEDED — the LoadGuard/value-set conclusion below was WRONG. a/b disambiguation (main-
directed) proved the answer is (a): remove a SPURIOUS mosura hint, NOT add a missing Ghidra one. Task #6
(LoadGuard/value-set) is NOT needed for task #5.**

**DECISIVE a/b VERDICT = (a)** — three independent proofs (2026-07-24):
1. mosura ALREADY has the correct `size=2 Unknown(2) hi=3` hint at -0x58 (from the indexed 2-byte LOAD).
   It's beaten by a SPURIOUS `size=8 Unknown(8) hi=-1` hint whose base pointer descends ONLY to an
   INDIRECT (the `func_0x00101000(auStack_58,...)` call-clobber marker) and is typed `Pointer(Unknown(8))`.
   EXPERIMENT (env-gated probe, reverted): suppress that spurious hint → mosura emits EXACTLY Ghidra's
   `xunknown2 axStack_58[10]` + `return axStack_58[i]` (was `xunknown8[2]` + `*(T*)(base+i*2)`);
   RulePtrArith/AddTreeState then form the PTRADD unchanged. So NO LoadGuard/value-set needed — the
   element-2 hint already exists.
2. Blast radius: with the spurious hint suppressed, corpus 0.9516 → 0.9518 (+0.0002, toward-oracle, 57/60)
   — a general improvement.
3. gcc MVE (`scratchpad/repro/arr_main.c` + `arr_ext.c`, class-A GENERAL, not Watcom): `short buf[10];
   ext(buf,0x20); return buf[sel[1]];` with a REAL external `ext()`. Ghidra → `undefined2 auStack_28[16]`
   + `ext(auStack_28,0x20)` + `return auStack_28[i]` — element-2 array DESPITE the call-clobber. Ghidra
   never types the call-arg pointer as `undefined8 *` and never generates a size-8 hint.

**PIN — CRUCIAL REFRAME (2026-07-24, hooked infertypes type-assignment, reverted):** the
`Pointer(Unknown(8))` is SEEDED by `TypeOpLoad`/`TypeOpStore::propagateType` — an 8-byte LOAD/STORE
types its pointer `Pointer(Unknown(8))` (trace: `vn49 via Load from alttype=Unknown(8)`, `vn728 via
Store`). mosura's ONLY 8-byte accesses in partialsplit are the STACK-CANARY loads (`LOAD u0xc900`,
`u0xc900 = FS_OFFSET + 0x28`) — those correctly type the CANARY pointer `Pointer(Unknown(8))`. The
-0x58 array base then gets `Pointer(Unknown(8))` via `vn840 Ptrsub` (the element-8 FIXPOINT) + `vn832/
vn726 Indirect` RELAYS. **So the pointee typing is FAITHFUL (not a spurious default) — my earlier
"correct the Unknown(8) pointee default" framing was WRONG.** The real issue is the fixpoint/propagation:
the -0x58 base becomes `Pointer(Unknown(8))` and reinforces `Array(Unknown(8),2)`, even though iter0's
symbol is element-1 and there is NO 8-byte access at -0x58. The exact spurious step (which INDIRECT/
relay/fixpoint edge first makes the -0x58 base element-8, and what Ghidra does differently) needs a
FRESH focused propagation trace — the env-gated suppress-hint probe proved (a) empirically but the
FAITHFUL fix is here in the propagation/fixpoint, NOT a one-line pointee change. type_order/preferred/
gatherOpen/spacebase_sub_pointer are all FAITHFUL and confirmed do-not-touch. NEXT: trace the -0x58
base's first `Pointer(Unknown(8))` edge across iterations (hook the type-assignment filtered to the
-0x58-mapped varnodes) + diff against Ghidra's propagation; then the faithful fix + regression-guard +
gate. This is delicate corpus-wide type-inference core — plan/ground fully before code.

**PIN PROGRESS (2026-07-24, per-iteration instrumented `gather_open`, reverted):** the fixpoint
transition is `iter0: base=Unknown(8) SCALAR (def IntAdd(Pointer(Spacebase),Unknown(8)))` → `iter1:
base=Pointer(8,Unknown(8))` (the spurious idx=false call-clobber base) vs the correct idx=true base
`Pointer(8,Unknown(2))`. CRUCIAL: the `Unknown(8)` POINTEE is **NOT** from `spacebase_sub_pointer`
(which returns `Unknown(1)` for a no-mapped-symbol offset, line 548; and iter0's symbol is
`Array(Unknown(1),20)` = element-1, which would give `Unknown(1)` not `8`). So the `Unknown(8)` pointee
comes from a DIFFERENT type-propagation source on the idx=false base — REMAINING PIN: hook the varnode
type-assignment in infertypes to catch which rule first sets `Pointer(_,Unknown(8))` on that call-clobber
varnode (candidates: a generic "make-pointer" default that uses `Unknown(vn.size)` as pointee instead of
`Unknown(1)`; the INDIRECT-output typing; or a propagate_add relay). Best done fresh (delicate corpus-wide
type core — a wrong pin risks the regression main flagged). Once pinned: correct that pointee-typing to
match Ghidra (which types the same pointer with the array element, element-2, per the gcc MVE), regression-
guard legit `undefined8 *` stack args, stage + gate. type_order/preferred/gatherOpen stay untouched.

**FAITHFUL FIX DIRECTION (main gated (a); condition = pin exact origin first):** mosura types the call-clobber stack pointer's
pointee as `Unknown(8)` (unconstrained-by-dereference → ptrsize default), producing a competing size-8
array hint. Ghidra's equivalent pointer carries the array element type (2), so no size-8 hint. The fix is
in that pointee typing — REMAINING GROUNDING: pin the exact origin of the `Unknown(8)` pointee (CALL param
model? INDIRECT-output default? unconstrained-pointer pointee default in infertypes? or purely the
element-8 fixpoint self-reinforced by the index-less call-clobber hint) and correct it faithfully WITHOUT
regressing legit `undefined8 *` stack args (the corpus-wide risk). The env-gated "skip INDIRECT-only base"
probe is NOT the faithful fix — just the proof of (a). type_order/preferred/gatherOpen are FAITHFUL and
must not be touched. [[task22-typespacebase-campaign]] varmap follow-on. Task #6 (LoadGuard/value-set) =
NOT NEEDED here (delete/deprioritize).

## OPEN QUESTIONS / CEILINGS
- **E1052 (~35) = honest ceiling — DOCUMENTED verified-faithful**
  (`docs/decompiler-nonbug-e1052-void-indirect-call-faithful.md`). Full-analysis Ghidra emits the
  identical `iVar = (*(code*)p)();` and that construct fails to compile under gcc too (`void value not
  ignored`, wcc386 E1052 class). Recovering the callee return type needs deep prototype analysis;
  mosura already matches Ghidra. NOT decompiler-reachable via faithful porting. **Reclassified OUT of
  the actionable set → true remaining actionable COMPILE_FAIL after Brick 1 = 112 − 35 = 77.**
- Whether some of the "later brick" classes (E1029/E1010/E1045) are also partly ceilings — check each
  against the reproducer + Ghidra before coding.

## LEAD grounding advance (2026-07-24, while war2-typeinfer rate-limited)

Advanced task #5(a) read-only (no type-core edit — the delicate fix is held for the agent's fresh resume per its own recommendation). Two concrete additions:

1. ORACLE TARGET NAILED (oracle/capture --c partialsplit): Ghidra emits `uint2 auStack_58 [10]` + `return (uint8)auStack_58[*(int4 *)(param_1 + 4)]` + `func_0x00101000(auStack_58,0x20,(int4)*param_1)` (Ghidra also RECOVERS the call's 3-arg prototype; mosura shows `func_0x00101000()` no-args). mosura @32ff095: `xunknown8 axStack_58[2]` + raw `*(xunknown2*)(axStack_58 + i*2)`.

2. SUBTLETY that sharpens the a/b question — the 8-byte STORE is a faithful size-8 source present in BOTH tools: Ghidra's own output has `*(xunknown8 *)puVar3 = 0xffff020000000100;` (puVar3 = auStack_58), an 8-byte scalar STORE at offset 0 of the base. mosura's `propagate_load_store` value_to_ptr (infertypes.rs:438, STORE inslot==2) → `propagate_to_pointer(Unknown(8), sz)` = `Pointer(sz, Unknown(8))` — a FAITHFUL port of TypeOpStore::propagateType. So this size-8 hint is NOT mosura-only; Ghidra has the same 8-byte store yet still gets `uint2[10]`.
   ⇒ SHARPENED OPEN QUESTION for the fix: it's not merely "mosura has a spurious size-8 hint Ghidra lacks" (the earlier (a) framing). The size-8 SCALAR-at-offset-0 store-hint (hi=-1) exists in both; the divergence is WHY Ghidra's reconcile lets the size-2 ARRAY (hi=3) win over the size-8 scalar-at-0, while mosura's picks the size-8 scalar. Either (i) Ghidra's varmap subsumes a size-8-scalar-at-0 into an array whose total span ≥8 (arrayness from the indexed access dominates a single wide scalar write at the base), or (ii) mosura generates an ADDITIONAL size-8 hint (the call-clobber INDIRECT the agent traced) that tips it. The focused instrumentation trace must log ALL open hints at -0x58 with their (size, hi, source-op) and compare to Ghidra's RangeHint set — distinguish the store-hint from the call-clobber-hint, and check whether the real fix is in gatherOpen/addRange arrayness-vs-scalar subsumption (RangeHint::merge / reconcile of overlapping array+scalar), NOT a pointee default. type_order/preferred confirmed faithful — untouched.

NET: fix target confirmed against oracle; the a/b verdict needs refining (the 8-byte store is a red-herring-shared source; focus on the array-vs-scalar-at-0 reconcile + whether a call-clobber hint is the real extra). Held for fresh implementation — a rushed edit here risks corpus-wide type-core regression.
