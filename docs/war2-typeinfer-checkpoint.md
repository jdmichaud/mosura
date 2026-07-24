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

## LEAD deep-dive #2 (2026-07-24): partialsplit array-element root cause FULLY pinned + isIndirectCreation guard landed

Instrumented mosura's varmap hints + infertypes propagation on partialsplit end-to-end (probes since removed). FINDINGS:

1. THE COMPETING HINTS at -0x58 (VARMAP probe): `size=2 highind=3 Open Unknown(2)` (correct array, from the indexed 2-byte LOAD, base vn165 Pointer(Unknown(2))) vs `size=8 highind=-1 Open Unknown(8)` (spurious scalar, base vn832 Pointer(Unknown(8))). Both Open + same start → RangeHint::preferred falls to type_order(Unknown(2),Unknown(8)) → bigger-Unknown wins → element-8. type_order/preferred/gatherOpen all CONFIRMED faithful vs Ghidra source (gatherOpen DOES create open hints from non-indexed bases too — varmap.cc — so NOT a gather_open bug).

2. THE ELEMENT-8 SEEDS (SEED probe, first element-8 assignments): (a) the two 8-byte CANARY loads vn49/vn116 (FS_OFFSET+0x28 — faithful, not the base); (b) **the 8-byte STORE `*(xunknown8*)base=0xffff...` (vn728) via TypeOpStore::propagateType value→ptr → Pointer(Unknown(8))** — a GENUINE 8-byte access to the base, faithful, and PRESENT IN GHIDRA TOO; (c) a Ptrsub@0x100041. So the size-8 hint is store-dominated, NOT primarily the call-clobber relay.

3. THE REAL DIVERGENCE (upstream, deep): Ghidra keeps the base pointer `uint2*` (the array element type) and renders the 8-byte store as a CAST `*(xunknown8*)puVar3` (puVar3 is `uint2*`). mosura lets the store's element-8 propagation win the base pointer's type → element-8 array. It's an ITERATION FIXPOINT: iter0 element-1/2 array → store propagates element-8 to base → iter1 flips to Array(Unknown(8),2). Ghidra breaks it because the varmap-recovered array-symbol type (uint2[10]) DOMINATES and ActionSetCasts inserts a cast at the mismatched 8-byte store rather than retyping the pointer. THE FAITHFUL FIX is in that dominance/ordering (array-symbol type over per-op store propagation) + cast-at-mismatch — a multi-system (varmap↔infertypes↔ActionSetCasts) resolution, NOT a one-liner. This confirms the agent's "delicate corpus-wide type-core" assessment.

4. LANDED (804d274, byte-neutral, faithful): the MISSING `TypeOpIndirect::propagateType` guard `if(op->isIndirectCreation()) return 0` — mosura lacked it, relaying stale pointee types across call-clobber creations. Inert on partialsplit (store-dominated) but a genuine missing faithful rule; MAY reduce other WAR2 COMPILE_FAILs where the INDIRECT relay is the dominant element-8 source → WAR2 re-measure on resume to confirm. Unit test added.

NEXT (fresh): the deeper array-symbol-type-dominance + cast-at-mismatch fix (#3 above) — differential-first, staged, corpus-gated. Store-vs-array element resolution is the crux, not the call-clobber.

## LEAD session #2 (2026-07-24, agent rate-limited) — bounded wins cleared, remaining = deep foundations

LANDED (master 09f23c6): isIndirectCreation guard (804d274) + E1063 for-loop marker-leak (09f23c6, ground-truth-gated forphi.c). Both faithful, corpus-neutral, tested.

REMAINING COMPILE_FAIL classes are ALL deep foundations or deep structurer bugs — NO bounded win left (confirmed):
- **E1045 ×12 (array-element typing / partialsplit):** fully pinned to a multi-system fixpoint (store element-8 vs array-symbol dominance + cast-at-mismatch). Ghidra keeps the base `uint2*` because the array-SYMBOL type dominates the per-op store propagation and ActionSetCasts casts the 8-byte store; mosura lets store-propagation win. Fix = ordering/dominance of varmap array-symbol type over infertypes store propagation (varmap↔infertypes↔ActionSetCasts). DEEP.
- **E1018 ×2 (goto to undefined label):** the goto-TARGET block (e.g. 0x43f3a in FUN_00043f04) is DROPPED from the structured output entirely (`LAB_..:` emitted 0×) — a structurer collapse bug excluding a reachable goto-target block (kin to D2 dead-block: likely a constant-folded/absorbed block with a surviving goto edge). DEEP structurer.
- **E1010 ×16 + E1081 ×6:** aggregate/concrete-pointer type lattice (cast.rs "primitive lattice only; struct/enum deferred"). DEEP.
- **E1029 ×17:** directional read/def-facing type model (mosura has none). DEEP.

⇒ The campaign has cleared every shallow/bounded lever. Further COMPILE_FAIL progress requires committing to ONE deep foundation (multi-session, staged, gated). Highest-value + fully-characterized = the array-element typing (E1045+Brick2). Next best count = the aggregate lattice (E1010/E1081, ~22).

## agent war2-arraytype (2026-07-24) — task #5 root cause CORRECTED: the array machinery is FAITHFUL; the gap is UPSTREAM (call/return output lifecycle, menu E)

Instrument-first end-to-end re-grounding of partialsplit (probes since REVERTED; tree clean `59981803`). The
checkpoint's pinned root cause ("array-SYMBOL type must dominate per-op store propagation + cast-at-mismatch")
is **INCOMPLETE and its prescribed fix is unnecessary.** The dominance Ghidra exhibits is AUTOMATIC — it needs
NO new machinery — and mosura's varmap/infertypes/type_order/spacebase_sub_pointer are all faithful and already
produce it once one upstream input is right. The complete, empirically-verified causal chain:

1. **The dominance is via `Datatype::compare` (type.cc:212), which orders `submeta` BEFORE `size`.** Ghidra's
   stack-array element is `uint2` (submeta `SUB_UINT_PLAIN`=16); the competing 8-byte store hint is `Unknown(8)`
   (`SUB_UNKNOWN`=21). `Pointer(uint2).typeOrder(Pointer(Unknown(8)))` < 0 → the concrete element wins REGARDLESS
   of 8>2, both in the infertypes `propagateTypeEdge` trim (`0>newtype->typeOrder`, coreaction.cc:5104) and in
   the varmap `RangeHint::preferred` tiebreak. So the store's `Pointer(Unknown(8))` is trimmed, the base stays
   `uint2*`, no size-8 hint is gathered. mosura's element is `Unknown(2)` (same submeta as `Unknown(8)`), so size
   decides and the bigger unknown wins → element-8 fixpoint. **The ONLY divergence is element concreteness:
   `uint2` vs `Unknown(2)`.**

2. **Ghidra's `uint2` comes SOLELY from the loaded value being consumed by a live `INT_ZEXT`.** `Varnode::getLocalType`
   (varnode.cc:900) takes the most-specific over the def's `outputTypeLocal` and every use's `inputTypeLocal`;
   `TypeOpFunc::getInputLocal` (typeop.cc:371) returns `getBase(size, metain)` and `TypeOpIntZext`'s `metain =
   TYPE_UINT` (typeop.cc:1115). So the ZEXT input seeds the loaded value `uint2`, which `TypeOpLoad::propagateType`
   pushes to the base as `Pointer(uint2)`. **mosura already ports all of this** (`op_meta(IntZext)=(Uint,Uint)`,
   `get_local_type`) — it simply never fires because the ZEXT is gone (see 3). CONFIRMED by probe: forcing the
   loaded value to `Uint(2)` makes mosura emit EXACTLY Ghidra's `uint2 auStack_58[10]` + `return auStack_58[i]`.

3. **mosura kills the widening `ZEXT28` because its return-consume is narrow (0xffff), which lets `RuleSubvarZext`
   narrow the ZEXT (2→8) into a dead 2→2 COPY.** mosura's `try_return_pull` consume-guard (subvarflow.rs:545) IS
   a faithful port of Ghidra's `tryReturnPull` (subflow.cc:238: `if ((getConsume()&~mask)!=0) return false`).
   `gather_consumed_return` (consume.rs:257) is ALSO a faithful port of `gatherConsumedReturn` (coreaction.cc:3871)
   — OR of `minimalmask(nzm)` over each RETURN's value. Both faithful. Measured consume on the ZEXT output = 0xffff.

4. **The narrow consume is because mosura's SECOND return is VOID.** Ghidra returns `0xffff020000000100` (8-byte
   const → `minimalmask` = full → return-consume full → ZEXT-guard BLOCKS → ZEXT stays live → element uint2).
   mosura's second RETURN carries no value (`RETURN r0x288:8`, raw IR): the `func_0x00101008()` call clobber makes
   the else-block's base an `extraout_RDI` artifact and the RAX at the second return holds the CALL output, not the
   later constant, so `return_trial_kept` (realism/ancestor gate) prunes it to void. **THIS is the call/return
   output-trial-lifecycle — the KNOWN deep menu-E foundation (persistent isOutputActive/ParamActive), and the same
   `extraout_` class that dominates 626 WAR2 MISMATCH functions.**

**VERDICT:** partialsplit's E1045 array-typing symptom is DOWNSTREAM of menu-E (call/return output recovery), not
an array-typing-foundation gap. Without a live widening ZEXT (which needs the second return recovered), the element
cannot be concrete, and no faithful array-typing change can help (Ghidra's element concreteness has the same single
source). type_order/preferred/gatherOpen/spacebase_sub_pointer/RulePtrArith/AddTreeState/get_local_type/op_meta/
gather_consumed_return/try_return_pull are ALL faithful and confirmed do-not-touch. **Task #5 as scoped (array-element
type inference) is NOT the lever; the lever is menu-E.** A speculative bounded angle (RETURN_MAXPASS>0 keeping
active_output set → `gatherConsumedReturn` returns full through type recovery → ZEXT survives even with the void
second return) is the mainloop-cadence gate ([[task8-mainloop-repeat]]) and risks corpus-wide churn — NOT pursued
without lead alignment. Reframe reported to main; proceeding to the queued E1018 structurer bug pending the menu-E
prioritization decision.

## agent war2-arraytype (2026-07-24) — task #7 menu-E GUARDRAIL evidence: general pipeline SOUND, partialsplit is multi-confounded (NOT a clean isolated divergence)

Per task #7's guardrail ("PROVE isolated-oracle divergence FIRST; build a minimal Ghidra-decompilable MVE"), I built
three gcc-x86-64 MVEs of increasing fidelity to partialsplit (scratchpad/vret*.c, System V so mosura+Ghidra recover
the same proto). Decisive result — **mosura's general array/return/ZEXT pipeline is SOUND; the bug does NOT reproduce
in isolation:**
- vret.c (2 returns, post-call constant return): mosura CORRECT (`return -0xfdff`, both returns).
- vret2.c (8-byte return, 2-byte value path + 8-byte const path): mosura CORRECT — element concrete `uint2`, both
  returns. The widening ZEXT stays live because the real second return makes return-consume full. Exactly Ghidra.
- vret3.c (stack `buf[16]` + call-clobber + store-and-return the same 8-byte const): mosura CORRECT —
  `uint2 auStack_38[28]` + `(auStack_38)[i]` + both returns via a phi. The full array+concreteness+return chain works.

So there is NO general array-typing, ZEXT-concreteness, or return-recovery gap. partialsplit fails only by STACKING
several menu-E reg-artifact mechanisms that the MVEs don't jointly trigger:
1. The stack base is carried in caller-clobbered RDI across BOTH calls as `r0x38 = INDIRECT(r0x20=RSP)` (ps IR
   257/258). mosura keeps this as a SEPARATE `Pointer(Unknown(8))` HighVariable from the PTRSUB-derived `auStack_58`,
   so the 8-byte store through it propagates element-8 instead of being a cast through the array pointer. Ghidra
   unifies both as `puVar3` (`uint2*`) and casts the store.
2. printc `name_of` (printc.rs:408) names ANY register-INDIRECT-output `extraout_<reg>` — INCLUDING this
   value-relaying INDIRECT (relays RSP). Ghidra reserves that only for a call-CREATED (isIndirectCreation) clobber;
   a relayed live value keeps its identity. So mosura renders the base `extraout_RDI`.
3. The void second return (RAX at the 2nd return not carrying the returned constant) cascades from the same
   RDI/RAX call-clobber modeling → narrow return-consume → dead ZEXT → Unknown(2) element.

VERDICT for the gate: menu-E on partialsplit is a **multi-mechanism deep fix** (stack-base unification across
call-clobber INDIRECTs + relayed-INDIRECT-vs-creation naming + the void-return), NOT a single bounded lever, and it
does NOT isolate to one clean MVE divergence (the guardrail's precondition). A CLEANER isolated MVE that forces a
caller-clobbered register to hold the stack base across a call and be reused post-call is needed before committing —
gcc -O1 keeps recomputing the stack address (dead-stores the local) so it won't reproduce the exact shape. RECOMMEND:
before any menu-E code, either (a) find/craft the isolated single-mechanism MVE (candidate: mechanism #1, stack-base
unification, is the most direct E1045 lever — test whether unifying the INDIRECT-relayed RSP base with the stack
symbol alone flips element-8→uint2), or (b) if that MVE can't be built, treat menu-E as genuinely deep-foundation and
weigh vs E1010/E1081 (~22, no such isolation problem). Held for lead go/no-go. type-core/varmap/return-recovery all
confirmed faithful throughout.

## agent war2-arraytype (2026-07-24) — BRICK: extraout_ naming gated on isIndirectCreation (task #8) — GATE REQUESTED

Faithful port of Ghidra `database.cc:2492` (`(flags & Varnode::indirect_creation) != 0` guards `extraout_` naming).
mosura's `printc.rs::name_of` named ANY register whose def is an INDIRECT `extraout_<reg>`; now gates on
`vn.is_indirect_creation()` — so a value merely RELAYED across a call by a guarding INDIRECT (input = live pre-call
value) is named as an ordinary local, not the `extraout_` artifact. Same `is_indirect_creation` predicate as the
804d274 TypeOpIndirect guard.

GROUNDING (all read-only, guardrail satisfied before code):
- Ghidra source: `database.cc:2492` names `extraout_` ONLY under the `indirect_creation` flag; a relay falls through
  to the local/merged naming (Var<n> / merged-symbol) — CONFIRMED.
- mosura divergence: printc.rs:408 gated only on `def.code()==Indirect` (any INDIRECT) — CONFIRMED.
- Isolated oracle (partialsplit): mosura emitted `*extraout_RDI = ...` (RDI = INDIRECT(RSP-derived base),
  `indirect_creation=false` — a relay); `oracle/capture --c partialsplit` names it `puVar3` (a local pointer), no
  `extraout_`. Real isolated divergence.

RESULTS:
- Corpus **0.9513 → 0.9517** (+0.0004), ONLY partialsplit moved (~0.891→0.915, toward-oracle: `extraout_RDI`→`pVar4`,
  a local pointer as in Ghidra), 57/60 maintained, ZERO regressions. Suite 495/0, clippy 0, regression test
  `printc::tests::relayed_indirect_register_is_not_named_extraout` added.
- **WAR2 blast radius = ZERO (hypothesis refuted).** Instrumented survey: all **208** WAR2 register-INDIRECT-output
  emissions are `creation=true` (genuine call-created clobbers) — NONE are relays. The 93-fn WAR2 extraout_ MISMATCH
  class is UNCHANGED (correctly named). So the "~626-fn blast radius" does not materialize; WAR2's extraout_ are
  faithful. The fix's only observable effect is fixing the relay mis-naming (partialsplit-class), not the WAR2 tail.
- Residual (NOT this brick): partialsplit's `pVar4` is used-before-def — the still-missing stack-base unification
  (mechanism #1); same IR/semantics as the pre-fix `extraout_RDI`, just renamed toward the oracle. Not wrong-code
  (IR unchanged); corpus judges it net toward-oracle.

VERDICT: faithful bounded fix, corpus toward-oracle, zero WAR2 impact. Partialsplit moved → GATED (gate-byte-identical
rule); reported to main with the delta for the commit go/no-go. Next per lead: E1010/E1081 aggregate lattice.

## agent war2-arraytype (2026-07-24) — E1010/E1081 FOUNDATION grounding (Brick A go/no-go pending lead gate)

Next foundation after e9c0655. Isolated-oracle-first grounding complete; build gated on lead go/no-go.

ISOLATED DIVERGENCES (clean datatests, oracle/capture --c):
- pointercmp (0.933): oracle `pxStack_10 = (xunknown1 *)(param_1 + 8)`; mosura bare `pStack_10 = param_1 + 8`.
- pointerrel (0.951): oracle `piStack_10 = (int4 *)(param_1 + 8)` + `(float4)piStack_10[-1] + fStack_18`; mosura omits
  both the `(int4 *)` assignment cast and the `(float4)` int→float value cast.

ROOT: mosura's cast layer (cast.rs `cast_standard` = faithful `CastStrategyC::castStandard`) is wired ONLY through
printc `get_input_cast` for op INPUTS (compares/shifts/div/arith-to-integral). NO assignment/store/copy output-cast
arm → a value assigned to a mismatched-pointer container renders bare (E1010 type-mismatch, the wcc386 reject).

GHIDRA SOURCE NAMED (typeop.cc, both `castStandard(reqtype, curtype, false, true)` — care_uint_int=false,
care_ptr_uint=true, the same signature mosura's cast_standard already implements):
- `TypeOpCopy::getInputCast`: reqtype = out->getHighTypeDefFacing(), curtype = in0->getHighTypeReadFacing().
  → mosura: `Copy` arm = `cast_standard(&type_of(output), &type_of(in0), false, true)`.
- `TypeOpStore::getInputCast` (slot 2 = value): when destSize == valueType size,
  `castStandard(pointedToType, valueType, false, true)` (pointedToType = ptrTo of the pointer operand's type).
  → mosura: `Store, slot==2` arm = `cast_standard(&pointee_of(type_of(in1)), &type_of(in2), false, true)`.
- (Directional getHighType{Def,Read}Facing collapse to mosura's single `type_of` — the primitive approximation;
  fine for the concrete-pointer-mismatch case, the E1029 directional model is a separate deferred foundation.)

STAGED PLAN: Brick A = Copy/Store assignment pointer cast (the E1010 compile lever; gate pointercmp/pointerrel
toward-oracle, wrong-code hard-block). Brick B = mixed int/float value cast `(float4)` (FloatAdd/IntAdd getInputCast;
similarity only — int+float compiles implicitly). RECOMMENDATION: GO Brick A first. AWAITING LEAD GATE before code.

## agent war2-arraytype (2026-07-24) — E1010/E1081 Brick A: NO clean render-cast lever (directional-type-gated) — STOP, report

Built + measured Brick A candidates (store-value cast `TypeOpStore::getInputCast` + for-init/copy cast
`TypeOpCopy::getInputCast`), all REVERTED — tree clean at e9c0655. Decisive finding: the render-cast layer does NOT
isolate on the datatest corpus, because mosura's SINGLE `type_of` already reconciles the very mismatches Ghidra casts.

- pointercmp/pointerrel (the only datatest E1010-adjacent divergences): instrumented the for-init — mosura types BOTH
  the loop var `phi_out` AND the init value `iv` as `Pointer(8, Unknown(1))` (identical), so `cast_standard` returns
  None — no render-cast can fire. Ghidra casts `(xunknown1 *)(param_1 + 8)` because it keeps the ADD result
  DEF-facing `int8` vs the loop var READ-facing pointer and reconciles via `getInputCast`. **mosura has no directional
  type model (getHighTypeDefFacing/ReadFacing) — a single `type_of`.** So these are the E1029 DIRECTIONAL-TYPE deep
  foundation, NOT a self-contained cast.rs extension. Both store/copy render-casts are INERT here (byte-identical).
- The genuine render-cast-fixable E1010 (WAR2 FUN_00016598 `pRam int* = pVar3 int1*` — distinct types, a real
  mismatch) is a GLOBAL/COPY assignment (not the store form), WAR2-ONLY (no isolated oracle), and its fix = the
  GENERAL copy-assignment cast at the `_ =>` arm — which fires on every explicit COPY assignment corpus-wide → the
  print-time re-inference WATCH-ITEM (broad movement), and can't be datatest-gated (byte-neutral there, WAR2-only).

VERDICT: E1010/E1081 render-cast is NOT the clean self-contained cast.rs brick expected. It splits into (a)
directional-type-gated datatest cases = the E1029 deep foundation (getHighType{Def,Read}Facing — a real type-model
extension), and (b) a WAR2-only genuine mismatch whose only fix (general copy-cast) is ungateable on datatests +
trips the re-inference watch-item. Neither is a bounded isolated-oracle brick. Reported to lead for re-gate; both
E1010 and E1029 now point at the SAME directional-type foundation. Tree clean, e9c0655.

## agent war2-arraytype (2026-07-24) — task #9 DEPTH-VALVE: "directional types" is UNION-ONLY, NOT the E1010 lever — STOP at plan

Grounded Ghidra's directional-type model from source (varnode.cc:626-672, type.hh) BEFORE any brick plan, per the
depth valve. DECISIVE — the scoped foundation is mis-named:

- `Varnode::getHighTypeDefFacing`/`getHighTypeReadFacing` (varnode.cc:651/665) BOTH return `high->getType()` (the
  HighVariable's type); they diverge ONLY when `ct->needsResolution()` → `ct->findResolve(def/op,slot)`.
- `needsResolution()` (type.hh:231) = "Is this a union or a pointer to union" (`needs_resolution` flag set only for
  TypeUnion / ptr-to-union / partial-union / array-of-size-1 — type.hh:551/945, type.cc:1052/1342/1571/1877/2427).
- ⇒ For pointercmp/pointerrel/E1010 (ordinary pointers + ints, NO unions), def-facing == read-facing ==
  `high->getType()`. The def/read DIRECTIONAL split is a UNION field-resolution mechanism — it does NOT produce the
  `(xunknown1 *)(param_1+8)` cast. "Directional read/def-facing types" is NOT the E1010/E1029 lever.

THE ACTUAL LEVER (re-pinned): `TypeOpCopy`/`TypeOpStore::getInputCast` compare HIGHVARIABLE types
(`out->getHighTypeDefFacing()` vs `in->getHighTypeReadFacing()` = `high->getType()` for both). The pointercmp cast
fires because Ghidra keeps the ADD result `param_1+8` typed **int8** in a DIFFERENT HighVariable from the loop var
(`xunknown1 *`). mosura types the ADD result **Pointer(8,Unknown(1))** — identical to the loop var — so no cast is
possible (instrumented: phi_out==iv==Pointer(8,Unknown(1))). mosura OVER-PROPAGATES the loop var's pointer type onto
the arithmetic init through the phi (same over-propagation class as partialsplit). So E1010 needs either (a) the
persistent HighVariable type model where an arithmetic result and a merged pointer variable keep distinct types
(the C-cluster / coarse-SSA foundation — mosura resolves ONE most-specific type per HighVariable, collapsing the
distinction), or (b) a delicate type-propagation fix (don't relay a pointer back through a MULTIEQUAL onto an
INT_ADD arithmetic result) — corpus-wide type-core risk, same delicacy flagged for partialsplit.

DEPTH VALVE TRIGGERED (as the lead anticipated): the two-type model resolves to the persistent HighVariable layer
(read-facing type IS `high->getType()`). STOPPED at the plan — reporting scope BEFORE opening the C-cluster. The
"directional type" brick plan would be building the wrong thing (union resolution). No code. Tree clean, e9c0655.

## agent war2-arraytype (2026-07-24) — task #10 C-cluster: mechanism = IR-CAST-op model; DEPTH VALVE all-or-nothing

Grounded the persistent-HighVariable/C-cluster mechanism to the ACTUAL faithful crux (source + instrumented):

1. INSTRUMENTED mosura infer on pointercmp: the INT_ADD result `param_1+8` (v34) has COMMITTED (per-varnode) type
   `Pointer(8,Unknown(1))` while its input param_1 (v218) is `Int(8)`. So the pointer is NOT from the HighVariable
   merge/resolution — it's TYPE PROPAGATION: the loop phi (MULTIEQUAL v243, pointer) relays its pointer type BACKWARD
   onto its input v34 (the INT_ADD result). It's a propagation issue, not a one-type-per-HighVariable issue.
2. GHIDRA SOURCE + oracle IR: `TypeOpMulti::propagateType` (typeop.cc) has NO guard — it relays `alttype` freely. The
   block comes from a REAL IR CAST OP: pointercmp oracle IR has `RAX = (cast) u0x10000008` where `u0x10000008 = RDI + #0x8`
   (the ADD result, int8). Ghidra's ActionSetCasts inserted a CPUI_CAST between the INT_ADD result (int8) and the loop
   phi (pointer); the phi's input is the CAST output (pointer), so the pointer never reaches the int8 ADD result.
3. THE ARCHITECTURAL DIVERGENCE: **mosura has NO IR CAST ops** — cast.rs is "just the decision, not an IR pass";
   printc realises casts at PRINT TIME. So nothing blocks the back-relay; the pointer propagates onto the arithmetic
   result; there is no type mismatch left for any render-cast to detect. Ghidra's CPUI_CAST is a real IR node that
   (a) is inserted by ActionSetCasts, (b) BLOCKS type propagation, (c) renders `(T)expr`.

FAITHFUL FIX = port Ghidra's IR-CAST-op model (ActionSetCasts inserts CPUI_CAST ops that participate in propagation).
This REQUIRES retiring mosura's print-time type re-inference (printc re-runs `infer()` at render time; an opaque IR
CAST perturbs that re-inference at compare sites — the exact block flagged in [[actionsetcasts-campaign]] Brick-2 +
[[printc-structuring-adaptation-conflicts]], a ZERO-GAUGE foundation change). 

DEPTH VALVE TRIGGERED (all-or-nothing): NO faithful incremental toward-oracle first brick exists —
- option (b) "guard the MULTIEQUAL→INT_ADD pointer back-relay" is a NON-FAITHFUL adaptation (Ghidra has no such
  guard; it uses the CAST op) → rejected by faithful-port-only.
- adding IR CASTs incrementally perturbs print-time re-inference corpus-wide (moves fixtures unpredictably, not
  toward-oracle) UNTIL the re-inference retirement lands; the retirement itself is zero-gauge (no toward-oracle value
  alone). So Stage 0 = retire print-time re-inference (zero-gauge, corpus-wide, risky) is a hard prerequisite with no
  incremental gateable value.

⇒ Per the lead's depth valve: STOPPED at the plan. The E1010/E1045/E1029/partialsplit convergence foundation is the
IR-CAST-op model + print-time-re-inference retirement — a genuine architectural rewrite, all-or-nothing at Stage 0,
no faithful bounded entry brick. Reported to lead for the user-level calculus decision. Tree clean, e9c0655.
