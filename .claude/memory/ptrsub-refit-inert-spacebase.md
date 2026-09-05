---
name: ptrsub-refit-inert-spacebase
description: "the ActionSetCasts PTRSUB refit is INERT (all 536 return true) — and its blocker is the ScopeLocal symbol query, NOT the composite lattice the inherited note named"
metadata: 
  node_type: memory
  type: project
  originSessionId: 99103a08-9d06-430b-8446-4ca5e3757106
  modified: 2026-08-03T18:03:18.246Z
---

Read-only verdict at `8d9e42c` (2026-08-03). **The PTRSUB refit (coreaction.cc:2748) would fire
ZERO times. Porting it is a no-op.** No code written.

Chain, each link measured or cited:

1. All **536** PTRSUBs reaching `ActionSetCasts` have a **SPACEBASE** pointee — 536/536, 197
   functions, `MOSURA_PTRFIT` at HEAD. None points to a composite.
2. The guard is `isPtrsubMatching(off, 0, 0)` — `extra` and `multiplier` are both **0** there.
3. `TypePointer::isPtrsubMatching` (type.cc:1123) takes its SPACEBASE branch: fail iff `getSubType`
   is null or the residual offset ≠ 0, then fail iff `extra >= subType->getSize()`.
4. mosura's `Datatype::get_subtype` (types.rs:184) returns `Some((Unknown(1), 0))` for **every**
   Spacebase — the always-present stand-in, because `Datatype` has no `glb` back-pointer and symbol
   resolution is deferred to print time (`printc::render_ptrsub` over `varmap::recover_scope`).
5. ⇒ never null, residual always 0, `0 >= 1` false → **true for all 536**.

⚠️ **THE INHERITED REASON WAS WRONG — the fourth item in that one bundled sentence to be
re-described.** The note deferred it "with the composite/union lattice they concern." The live
branch is SPACEBASE and its blocker is the **ScopeLocal symbol query**, which has nothing to do with
struct/union typing.

**Do not generalise from the PTRADD result to this one** — the near-miss worth remembering. The
PTRADD guard is a **size comparison**, fully meaningful for primitives, which is why it fired 59
times and caught a real 4× mis-scaling ([[base-getinputcast-was-the-catchall]]). Every PTRSUB
branch that could accept needs a spacebase symbol lookup we don't do in the type layer. **Two
refits, two different kinds of thing; never quote them in one sentence again.** This is
[[hard-rules-never-stop-one-agent]]'s bundling trap recurring: a sentence covering several items
retires none of them.

**Revival condition — this certificate dies when** `Datatype::get_subtype` stops returning the
permissive Spacebase stand-in, i.e. when the ScopeLocal symbol query moves out of print time into
the type layer. A PTRSUB whose offset does not land exactly on a mapped stack symbol then returns
false, the refit goes live, and **it must be ported in the same commit as that change** — otherwise
mosura renders a PTRSUB into a frame slot no symbol covers. Anyone doing ScopeLocal-in-types reads
this first.

**Measured against:** the subject's 1303 functions at `8d9e42c`. The guard's reach on the 79 datatests is
**UNMEASURED** and this certificate does not cover it ([[numbers-stale-unless-sha-stamped]]).
