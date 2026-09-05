---
name: base-getinputcast-was-the-catchall
description: "cast.rs's `_ => None` claimed \"everything else is transparent\"; Ghidra's base TypeOp::getInputCast is the opposite default — and the PTRADD refit fixed a silent mis-scaling"
metadata: 
  node_type: memory
  type: project
  originSessionId: 99103a08-9d06-430b-8446-4ca5e3757106
  modified: 2026-08-03T18:03:01.606Z
---

Landed 2026-08-03: `ab6ea9c` (base `getInputCast`) and `8d9e42c` (`opUndoPtradd` + the
ActionSetCasts PTRADD refit), on master from `9e0c169`.

**`_ => None` was an ASSERTION, and it was backwards.** Ghidra: a `TypeOp` uses the **base**
`getInputCast` (typeop.cc:295 = `castStandard(inputTypeLocal(slot), curtype, false, true)`) unless
it *declares* an override, and of the 25 that do, only `TypeOpCpoolref`/`TypeOpNew` say "never
needs casting" (typeop.hh:867/878). The placeholder came in with `79f5406`, which wired only the
comparisons; it was never a decision about INT_ADD, INT_LEFT, the FLOAT ops, or the shifts' slot ≠ 0
(whose overrides *delegate* to the base, typeop.cc:1555/1597). Cost: 3 casts on the 79 datatests,
**693 on the subject**, every one the same shape — a pointer consumed by integer arithmetic, needing
`(int4)`.

**Why: the port's default must be the base, never "nothing."** When a dispatch mirrors a C++ class
hierarchy, the catch-all arm has to be *the base method*, and every opcode kept out of it needs its
own stated reason. Both hold-back arms in `cast.rs` are written that way — one line, one revival
condition each: (a) ops whose `getInputCast` override is unported (COPY/LOAD/STORE/ZEXT/INT2FLOAT/
PIECE/SUBPIECE/PTRADD/PTRSUB/SEGMENTOP); (b) ops that *do* use the base but also override
`getInputLocal`, which `infertypes::input_type_local` does not model (CBRANCH/CALLIND/CALLOTHER/
RETURN/INDIRECT/INSERT/EXTRACT — inert today, listed so fixing `op_meta` cannot switch them on
silently).

**How to apply:** grep any `_ => None` / `_ => {}` in a file that mirrors a Ghidra class hierarchy
and ask what the BASE method does. Before changing one, bound it read-only first — a throwaway
`eprintln!` in the arm, run over the corpus *and* the subject, tallied by opcode — then Rule-Zero each
corpus specimen against `oracle/capture --c`. That sequence turned a 2-fixture question into a
693-firing single-class change with three oracle-confirmed specimens, and it is reusable.

**⭐ The PTRADD refit fixed a silent mis-scaling that NO gate could see.** `FUN_00072220` emitted
`*((xunknown4 *)(xVar5 + 3))` where the PTRADD meant +3 **elements** of 4 bytes and `xVar5` is
`Unknown(4)` — not a pointer — so `+3` added 3 **bytes**: wrong by 4×. Now `+ 0xc`. 56 of the 59
misfitting PTRADDs have a pointer base whose pointee size disagrees with the element size, 3 have a
non-pointer base. Invisible to the wrong-code scan (labels / fall-off-end / empty constructs) *and*
to the recompile (all 14 functions score MISMATCH before and after). **Found only by porting the
guard Ghidra wrote** — the case for [[direction-faithful-port]] in its purest form: no gauge asked
for it and no gauge could have.

⚠️ **No oracle-checkable specimen exists for that refit and it must not be claimed otherwise.** The
guard fires **0 times on all 79 datatests** and only on the subject, where `capture --c` cannot run
(DOS/4GW LE) and `ghidra-all.txt` is analyzeHeadless with a Java TYPE model — while the guard is
itself a type test. Same confound as the cast question; see
[[oracle-same-question-not-just-same-tool]].

Battery across both commits: corpus 0.9552 → **0.9561** (58/60) · cast census 9031 → **9905** ·
COMPILE_FAIL 46 → **45** · **byte-clean 16, member set identical throughout** · call gauge
**untouched** (deficit `{00079130}`, EMITTER 0, surplus set unchanged) · wrong-code gates 0 ·
reached==cfg 0/1303 · suite 505/0 · clippy 0.

Related: [[cast-census-is-per-line]] (the census caveat these deltas were read through),
[[ptrsub-refit-inert-spacebase]] (the sibling refit, and why it is NOT the same kind of thing).
