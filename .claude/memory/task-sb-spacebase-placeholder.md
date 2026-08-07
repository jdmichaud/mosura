---
name: task-sb-spacebase-placeholder
description: "Task #7 spacebase LOAD/STORE forwarding (RuleLoadVarnode/StoreVarnode). S1 ram-global branch LANDED cf14470. S2 (stack branch + re-versioning) HELD after Phase-1: re-heritage does NOT recover revisit — the whole stack track is gated on the mainloop-repeat rock."
metadata:
  node_type: memory
  type: project
  originSessionId: c0fe6b35-0fb2-4ed2-90d8-ec93de63680c
---

## ✅ S2a LANDED master `59cedd6` 2026-07-11 (sb7, lead GATE-CONFIRMED). Faithful ActionSpacebase MOVER. Corpus avg **0.9219 / 56** @59cedd6, suite 399/0, switch 6/6, tree clean, clippy no-new. SPENT after this arc — recommend fresh-run S2c next.
Lead GO'd S2a (bounded ActionSpacebase brick; correctSpacebase stack branch DORMANT) then GATE-CONFIRMED the land (accepted the full-faithful port + rejected the mark-only split as gauge-protecting drift). FULL faithful port of `Funcdata::spacebase()` (funcdata.cc:230) landed:
- **CODE (5 files):** `space.rs` — `Space.spacebase: Vec<(Address,u32)>`, register RSP `(register:0x20,8)` on the `stack` space in `standard()`, `set_spacebase`, `space_by_spacebase` (getSpaceBySpacebase, architecture.cc:264) + unit test. `funcdata.rs` — `Funcdata::spacebase()` (mark every non-free 8-byte RSP SSA version `is_spacebase()`; locked `Pointer(8,undefined1)` type on the INPUT only; splitUses re-mark branch omitted = unreachable single-pass) + unit test. `varnode.rs` — `Varnode::set_spacebase()`. `pipeline.rs` — `ActionSpacebase` wired before the first NonzeroMask/InferTypes/pool (coreaction.cc:5506). `coverage.md` — ActionSpacebase row PARTIAL→PORTED + varcross citation.
- **BLAST (name-keyed join vs clean `f4d511b`): avg 0.9220→0.9219, ONE mover = `varcross` 0.913→0.905 (−0.008); ALL 59 others score-identical.** Suite 399/0 (397+2), switch 6/6, clippy no-new. The ~6-consumer activation is nearly inert on the corpus (RSP is dead by print-time on almost every fixture; only stack-address-escaping fixtures keep it live).
- **ROOT-CAUSE (decomposed, mark-only vs mark+type):** varcross is a stack-array walk where `&xStack_68` escapes. **Marking alone (ptrarith) is CLEAN-POSITIVE** — the loop pointer becomes oracle-like `xunknown1 * pVar1` (was `int8 iVar1`) with NO naming loss (`while (pVar1 != axStack_18)` preserved). **The −0.008 is entirely the LOCKED POINTER TYPE on the RSP input** (infertypes): it breaks mosura's stack-scope recovery of the loop bound — `RSP-0x18` stops naming as the stack symbol `axStack_18` and prints as undefined `iVar2 + -0x18`. = **faithful-consumer-exposes-gap: mosura lacks `resolveSpacebaseRelative`/typed-spacebase-PTRSUB stack-array scope (S2b/S2c); Ghidra's type + resolveSpacebaseRelative + stack scope co-run in the mainloop so its varcross names the arrays.** NOT a mis-port (port matches funcdata.cc:230 exactly).
- **LANDED as reco'd** (`59cedd6`): full faithful ActionSpacebase, varcross −0.008 filed → S2c diagnostic. De-risk delivered for S2b: consumer activation is tiny + the ONE gap it exposes (typed-PTRSUB stack naming) is a named S2c prereq.
- **S2c SCOPED HANDOFF (for the fresh run — premise-first, instrument FIRST):** varcross's −0.008 = the typed RSP pointer diverts the `RSP + const` loop-bound ADDRESS (not a LOAD/STORE — recover_stack only converts LOAD/STORE, this bare address stays register arith) away from the stack-symbol naming that the UNTYPED baseline RSP already produced (`while(pVar1 != axStack_18)` → `iVar2 + -0x18`). Naming lives in **varmap.rs `recover_scope`/`restructure` (ActionRestructureVarnode localrecovery) + printc stack-local emission** (keyed on `stack`-space addresses). FIRST DELIVERABLE = instrument varcross post-S2a IR: does the typed RSP now generate a `PTRSUB(spacebase,off)` that varmap/recover_scope doesn't name (→ port PTRSUB stack-symbol naming = Ghidra resolveSpacebaseRelative/ScopeLocal), OR does the naming path just not handle the typed value (bounded printc/varmap fix)? That check decides bounded-fix-vs-subsystem. resolveSpacebaseRelative = fspec.cc:4870 (the SP-across-call placeholder; varcross does pass pVar1 to a call). S2b (correctSpacebase + cancel recover_stack) stays the HARD-gated high-risk restructure, separate.

## ⏸ S2c INSTRUMENT DONE 2026-07-11 (sb8, base `59cedd6`, READ-ONLY, tree clean, NO code). Reported bounded-vs-subsystem + WAITING for lead pick (a=bounded printc / b=TypeSpacebase subsystem / c=pivot). Startup clean: suite 399/0, corpus 0.9219/56, switch 6/6.
Instrumented varcross post-S2a (mosura `dumpc --raw` vs oracle `capture --ir -`/`--c`). VERDICT: the mechanical failure is a BOUNDED printc op-form gap; the FAITHFUL fix is the SUBSYSTEM. It's a MOVER (+0.008) + faithfulness fork → held.
- **IR EVIDENCE (loop bound):** mosura `u0x9d00:8 = PTRADD r0x20(RSP_input) #-0x18 #1` (element size 1); Ghidra `RSP(i) -> #-0x18` = **PTRSUB(RSP_input,-0x18)**. --c: Ghidra `while(pxVar1 != axStack_18)` vs mosura `while(pVar1 != iVar2 + -0x18)` (iVar2 = undefined RSP_input). So the typed RSP generates a **PTRADD, not a PTRSUB** (the lead's subsystem-criterion op is NOT what appears); varmap/recover_scope is unaffected; failure is 100% in printc.
- **ROOT CAUSE CHAIN:** (1) S2a locks RSP_input to `Pointer(8,Unknown(1))` (the TypeSpacebase stand-in). (2) Unknown(1)=unit element ⇒ RulePtrArith `build_degenerate` (ptrarith.rs:506) rewrites the single-use bound `INT_ADD(RSP,-0x18)`→`PTRADD(RSP,-0x18,elem=1)`. The frame-base `INT_ADD(RSP,-0x68)` stays INT_ADD because its output IS the spacebase-marked RSP with MANY uses → the faithful single-descendant spacebase guard (ptrarith.rs:143, ported from Ghidra) declines it — THAT asymmetry is why only the bound broke. (3) printc's print-time stack naming — `stack_addr` (printc.rs:537, called only from the IntAdd arm printc.rs:794) + `anchor_stack_arrays` (printc.rs:649, gated `if o.code() != IntAdd`) — recognizes only INT_ADD(RSP/RBP,const); the new PTRADD form falls to generic `base + index`.
- **TWO FIXES.** BOUNDED (~10 lines, restores exact -0.008): extend `stack_addr`/`anchor_stack_arrays` to also match `PTRADD(spacebase_reg,const,elem)` (== INT_ADD(spacebase,const)); low blast (only base=RSP/RBP + CONSTANT index matches; genuine `arr[i]` = non-const index/non-RSP base). BUT EXTENDS mosura's print-time stack-naming ADAPTATION, not a Ghidra port (Ghidra has no PTRADD-off-spacebase). SUBSYSTEM (faithful-forever): port TypeSpacebase + getSubType (resolveSpacebaseRelative/ScopeLocal, fspec.cc:4870) → RSP carries spacebase type → calc_subtype resolves symbol → RulePtrArith emits PTRSUB(spacebase,off) → printc/varmap name it. Touches types/infertypes/ptrarith/varmap/printc, every stack-local fixture. ALSO closes a PRE-EXISTING gap this exposed: Unknown(1) element poisons the loop-pointer type (`xunknown1 *pVar1`/`pVar1 + 4` vs Ghidra `xunknown4 *pxVar1`/`pxVar1 + 1`) — NOT part of the -0.008 (pre-existing), but the subsystem fixes it too.
- **RECO (sent):** take the bounded printc fix for S2c (coherent completion of S2a's stand-in), file TypeSpacebase subsystem as follow-on; but this is a real faithfulness fork so WAIT. Reproduce: `cargo run -q --example dumpc -- varcross [--raw]`; `oracle/capture <gh> datatests/varcross.xml --c|--ir -`.

## ⏸ TASK #22 GROUND+STAGE DONE 2026-07-11 (sb8, base `59cedd6`, READ-ONLY, tree clean, NO code). Lead REJECTED the bounded printc fix (a) as faithful-type-of-wrong-ir; filed #22 = TypeSpacebase subsystem. Grounded + staged; reported build-S22-1-now-vs-defer + WAITING.
Mechanism CONFIRMED (porting TypeSpacebase produces Ghidra's PTRSUB + faithful naming):
- **Ghidra:** `Funcdata::spacebase` (funcdata.cc:245) types RSP input `Pointer(8, TypeSpacebase(stack, localframe))` (NOT mosura's `Pointer(8,Unknown(1))` stand-in). TypeSpacebase size 0 (open-ended) + `getSubType(off)` (type.cc:2947) queries the fn's ScopeLocal symbol at that stack offset. `AddTreeState::calcSubtype` (ruleaction.cc:6285) has a `TYPE_SPACEBASE` branch mosura's `calc_subtype` (ptrarith.rs:383) OMITS; `hasMatchingSubType` (ruleaction.cc:6064) for spacebase is ALWAYS true (getSubType non-null even w/ no symbol → TYPE_UNKNOWN) ⇒ isSubtype=true ⇒ `PTRSUB(RSP,off)`. Printer `PrintC::opPtrsub` TYPE_SPACEBASE case (printc.cc:1058) reads symbol off the offset-varnode's high → `pushSymbol`(axStack_18)/`pushUnnamedLocation`.
- **★ DECOUPLING (enables a small first brick):** the PTRSUB IR shape does NOT need scope-in-pool — hasMatchingSubType trivially true, extra=0, off unchanged. mosura's `Datatype` is a plain enum with NO `glb` back-pointer (Ghidra TypeSpacebase holds `Architecture*`) so can't thread recover_scope INTO the datatype — but doesn't need to: pool uses trivial getSubType, NAMING is at PRINT via existing `recover_scope`(varmap.rs, mosura's ScopeLocal, already runs at print + already emits axStack_NN/xStack_NN via `stack_slot_name`). Right IR + print-time symbol-table naming = faithful, no scope-in-mainloop. ONLY loop-ptr TYPE propagation (`xunknown4 *pxVar1` vs mosura `xunknown1 *`) needs scope-in-mainloop = deferred.
- **splitUses** (funcdata_varnode.cc:1540, ~25 lines): Ghidra splits the multi-use frame base into 2 single-use PTRSUBs (`RSP(0x93)`,`RSP(0x94)`) — triggers on the 2ND `Funcdata::spacebase` pass (already-spacebase+INT_ADD def+multi-desc) = mainloop-coupled. mosura runs spacebase once → never splits → multi-use base stays INT_ADD (still named by the print-time adaptation until S22-2 retires it).
- **STAGING (gated):** S22-1 = `Datatype::Spacebase` variant (marker: space id; size/align 0; metatype TYPE_SPACEBASE; get_subtype→Some((Unknown(1),0))) + 8-file match-arm updates + funcdata.rs 1-line (RSP input→Pointer(8,Spacebase) not Unknown(1)) + calc_subtype TYPE_SPACEBASE branch (~10L) + render_ptrsub spacebase branch→recover_scope→stack_slot_name (~15L). Single-use refs→PTRSUB→named, FIXES varcross -0.008. KEEP INT_ADD print adaptation for multi-use bases (= S22-2 residual, NOT gauge-protect). GATE = the RSP-type-flip Unknown(1)→Spacebase infertypes ripple across RSP-derived COPY/phi values. **S22-2** = splitUses + spacebase 2nd-pass/mainloop re-run → multi-use→PTRSUB → RETIRE print-time `stack_addr`/`anchor_stack_arrays` adaptation. BIG BLAST (~20 stack-local fixtures: elseif/loopcomment/noforloop_alias/offsetarray/partialsplit/piecestruct/pointercmp/pointerrel/ptrtoarray/stackreturn/stackstring/switchhide/switchmulti/threedim/union_datatype/varcross/wayoffarray+). HARD-GATE, mainloop-coupled. **S22-3 DEFER** = Level-2 type propagation (getSubType returns symbol's real type in mainloop ≈ ActionRestructureVarnode-in-mainloop; closes loop-ptr poison).
- **RECO (sent):** build S22-1 now (bounded brick, faithful S2a-regression fix, de-risks by measuring the RSP-type ripple), defer S22-2/3. WAITING for lead build-now-vs-defer. Reproduce: oracle `capture <gh> datatests/varcross.xml --ir -` shows `RSP(i) -> #off` = PTRSUB; mosura `dumpc --raw` shows `PTRADD r0x20 #off #1`.

### ⛔ S22-1 BUILT + MEASURED 2026-07-11 (sb8) → NET-NEGATIVE, STOP+reported. Lead GO'd S22-1; built it; the STAGING BOUNDARY is FALSE. Tree DIRTY WIP (5 files), base 59cedd6, suite 399/0, WAITING for lead (A) merged-stage vs (B) revert+defer.
Built the full S22-1: `Datatype::Spacebase(SpaceId)` variant (types.rs — metatype renumbered Void=0/Spacebase=1/Unknown=2/…/Struct=8 + **lanedivide.rs ARRAY_META 6→7/STRUCT_META 7→8** consistent shift; submeta 22=SUB_SPACEBASE; size/align 0; get_subtype→Some((Unknown(1),0)); name "spacebase") + funcdata.rs spacebase() RSP-input→`Pointer(8,Spacebase(stack_sid))` (carry SpaceId) + ptrarith.rs calc_subtype TYPE_SPACEBASE branch (ruleaction.cc:6285) + printc.rs render_ptrsub spacebase branch keyed on `is_spacebase()` (NOT type_of — the RSP-input high is storage-merged with int frame-adjust versions → its printed type isn't the locked Spacebase ptr).
- **IR IS FAITHFUL:** varcross bound = `u0x9d00 = PTRSUB r0x20 #-0x18` = Ghidra `RSP(i) -> #-0x18` exactly. Datatype/calc_subtype/type-flip all correct. NOT a Spacebase mis-port.
- **MEASURED net-NEGATIVE:** avg 0.9219→**0.9182 (−0.0037)**, 56/60, suite 399/0. THREE movers ALL DOWN, none up: **enum 1.000→0.889** (−0.111, was PERFECT), **wayoffarray 0.920→0.833** (−0.087), **varcross 0.905→0.879** (−0.026, target itself).
- **ROOT CAUSE = the S22-1/S22-2 boundary is FALSE.** All 3 = an array-base `RSP+const` that baseline recovered as a stack ARRAY via `anchor_stack_arrays` (printc.rs:649, INT_ADD-only) → `xunknown1 axStack_18[8]`/`func(axStack_18)`. Producing the faithful PTRSUB moves the base OUT of anchor_stack_arrays → (1) the array DECL vanishes, (2) scalar render_ptrsub names it `&xStack_18` not `axStack_18`. Hits SINGLE-use array bases (enum) AND multi-use (wayoffarray -0x98 became PTRSUB too — the multi-desc spacebase guard did NOT keep it INT_ADD). So "produce PTRSUB + scalar naming + KEEP the adaptation" is impossible: PTRSUB strips arrays from the adaptation, which only matches INT_ADD. Faithful render_ptrsub MUST resolve recover_scope symbols (Ghidra opPtrsub printc.cc:1058: ARRAY→bare `axStack_NN` drop `&` + index; scalar→`&xStack_NN`) = the S22-2 array-naming. Extending anchor_stack_arrays to PTRSUB = the SAME faithful-type-of-wrong-ir anti-pattern lead rejected for (a). ⇒ **S22-1 (produce PTRSUB) and S22-2-array (faithful opPtrsub naming, retire anchor_stack_arrays) are ENTANGLED — one stage, not two.**
- **OPTIONS (sent, WAIT):** (A) build MERGED stage now (IR-half done in tree): port opPtrsub full array+scalar resolution over recover_scope, retire anchor_stack_arrays, drive ALL stack naming from the recovered symbol table — hard-gated ~20-fixture blast, only faithful path that lands non-negative. (B) REVERT S22-1, varcross stays diagnostic, defer subsystem, pick another rock. Lean: not a bounded brick; A if investing, else B.
- **WIP files (revertable instantly):** types.rs, lanedivide.rs, funcdata.rs, ptrarith.rs, printc.rs. Reproduce delta: full corpus report, or `dumpc enum|wayoffarray|varcross` vs `capture … --c`.

## ⭐ S2 POST-MAINLOOP RE-VERIFICATION 2026-07-11 (sb7, base `f4d511b`, READ-ONLY, tree clean, NO code). Premise HOLDS at the FOUNDATION but the "re-run the Phase-1 probes" framing is a CATEGORY ERROR. Report sent lead, WAIT for gate.
Lead asked: does the landed mainloop (`25cb50b`) now let S2's stack re-heritage recover revisit (what it couldn't pre-mainloop)? Premise-first, instrument-first. Startup: HEAD f4d511b, suite 397/0, corpus 0.9220/56, switch 6/6.
- **✅ RE-VERSIONING FOUNDATION = LANDED + PROVEN.** revisit (the ram-global re-versioning proxy the Phase-1 probes tested) is RECOVERED: mosura emits in-place `iRam...074 = iRam...074 + 10` (reads LINK to whole-range SSA, NO snapshot `iVar1=iRam;iVar2=iRam`). Oracle-diff: the ONLY residuals are **P6 void-return** (`uint8 func`/`return CONCAT62(...)` vs `void`/`return;`) + **P4 type** (`(xunknown2)(x>>0x10)` vs `x._2_2_`), NOT re-versioning. revisit 0.633 (pre-mainloop) → **0.677** now. Foundation = mainloop restart (pipeline.rs:437) + removeRevisitedMarkers brick (`32648d3`) + normalize_ranges + guardCalls-ram + S8-2a. **Part-1's gate is genuinely CLEARED.**
- **⚠️ "RE-RUN THE PHASE-1 PROBES" IS A CATEGORY ERROR — nothing to re-run.** Probe A (bare heritage restart) / Probe B (refine+normalize+heritage) tested RAM-GLOBAL revisit re-versioning — and that exact mechanism SINCE LANDED as the mainloop (`25cb50b`). There is NO stack re-heritage path in the pipeline to re-trigger: **`recover_stack` (stackvars.rs:160-178) converts RSP-relative LOAD/STORE→`stack`-space COPY PRE-heritage**, so stack accesses never reach ptrarith_pool → the landed mainloop restart NEVER sees a stack access. Grep-confirmed: `flags::SPACEBASE` set NOWHERE (only reader `is_spacebase()`); RuleLoadVarnode gates on `is_constant()` only (rules.rs:236, stack branch explicitly deferred rules.rs:215-217); no `correctSpacebase`/`vnSpacebase`/`getSpaceBySpacebase`/ActionSpacebase.
- **STACK TRACK (parts 2+3) = UNBUILT, HIGH-RISK RESTRUCTURE, deeper than one bounded port:**
  - Part 2 NEW machinery: port `Funcdata::spacebase()` (funcdata.cc:230-269 — mark RSP-input `Varnode::spacebase` + pointer type) + reg→space registration `getSpaceBySpacebase` (mosura stack space is SpaceKind::Spacebase but records NO RSP association) + `correctSpacebase`/`vnSpacebase` stack branch of checkSpacebase (ruleaction.cc:4173-4227, `RSP_input [+ const]`). Setting isSpacebase ACTIVATES ~6 dormant faithful consumers (ptrarith.rs:129/143, nzmask.rs:335, rules.rs:4689/7950, infertypes.rs:387/407) → potential MOVER on its own.
  - Part 3 MASS-REGRESSION risk: cancel recover_stack's (a) STORE/LOAD→stack-COPY conversion while KEEPING (b) SP-tracking + (c) call_push_restores (interleaved pass, delicate disentangle). impliedfield 0.938 / stackreturn 0.926 / stackstring 0.794 ALL rely on recover_stack's pre-pool forward.
  - Structurally the re-versioning WOULD extend to stack (pool-freed stack access → mainloop re-heritage, isomorphic to revisit's now-working ram path) — foundation is RIGHT, but only AFTER parts 2+3 built. It's a from-scratch build, NOT a probe re-run.
- **STAGING PROPOSED (gated per-stage, WAIT for lead pick):** S2a = port `Funcdata::spacebase()`/ActionSpacebase + getSpaceBySpacebase, correctSpacebase stack branch DORMANT (recover_stack still kills stack LOAD/STORE pre-pool) → GATED MOVER (activates is_spacebase consumers), premise-first bounded brick. S2b = add correctSpacebase stack branch to RuleLoadVarnode/StoreVarnode + cancel recover_stack conversion → stack LOAD/STOREs survive to ptrarith_pool → mainloop re-heritages (revisit's path) = HIGH-RISK mass-regression mover, gate on full stack-fixture set (stackstring 0.794 target). S2c DEFER = placeholder/resolveSpacebaseRelative.
- **VERDICT: foundation premise HOLDS; "unblocked by probe re-run" premise does NOT (stack track is unbuilt machinery, not a dormant path). Reported read-only + WAITING; if GO, enter at S2a (bounded brick + measure), NOT the full restructure.**

## ⛔ S2 PHASE-1 PREMISE OVERTURNED 2026-07-10 (sbs2, base `cf14470`, all probes REVERTED → tree clean) — re-heritage does NOT recover revisit; S2 is gated on the mainloop-repeat rock. Report sent lead, WAIT.
Phase-1 read-only premise verification of the 3 S2 parts (lead-directed, premise-first, NOT build-first). Verdict = **HOLD S2** — part-1's re-heritage fix (the memory's S1-landed hypothesis) is FALSE in mosura's current architecture; parts 2/3 rest on it. See [[direction-analysis-port]] mainloop-repeat.

**PART 1 (re-heritage-after-conversion) — DIAGNOSIS confirmed, FIX premise OVERTURNED.** Instrumented revisit (mosura dump vs oracle `capture --ir -`/`--c`): Ghidra versions the ram global — `r0x00100074:4(i)` (INPUT ver) read by the ADD, distinct store versions — so renders in-place `iRam..074 = iRam..074 + 10`. mosura's `r0x100074:4` is UNVERSIONED (S1's RuleLoadVarnode `new_varnode` = FREE, flags=0; the LOAD-derived read never existed at heritage time → the LOAD ptr copy-props to const 0x100074 only in the post-heritage pool) → merge-snip over-snapshots (`iVar1=iRam; iVar2=iRam; iRam=iVar1+10`). Provenance: revisit's read at 0x100015 is `LOAD #ram r0x8` (ptr=r0x100060=0x100074), S1-converted POST-heritage; the direct-ram forms at 0x100020/0x10002b existed at heritage time (2-byte) and WERE versioned — mixed width 2-vs-4 at 0x100074.
★ mosura's re-heritage machinery EXISTS + is triggered: `new_varnode` is free → `gather_candidates` flags `has_free` → `heritage_complete` returns false. The pipeline just never re-invokes heritage after `ptrarith_pool` (heritage restart group runs ONCE up front, line 359). BUT two throwaway probes (both REVERTED, tree clean) proved a re-invocation does NOT work:
  - Probe A (bare heritage restart group after cleanup_pool): revisit REGRESSES further — 3 snapshots (iVar1/2/3) + `xunknown8` return + spurious call save/restore; `r0x100074` STILL unversioned.
  - Probe B (`refine_overlaps` + `normalize_read_size` + heritage() before the restart): IDENTICAL bad output — refinement is NOT the lever.
  ROOT CAUSES (systemic, not one-line): (a) rename (heritage.rs:1205) reuses the pre-INSERTed write output, doesn't mint a fresh version for the S1 STORE→COPY out; (b) the widened 4-byte range re-enters `new_addrs` at `globaldisjoint.add` intersect=1 → `guard_calls` DOUBLE-fires → spurious INDIRECT save/restore around the call; (c) mixed 2/4-byte accesses not unified into one canonical var + SUB42 (Ghidra normalizeReadSize/mainloop). = mosura's one-shot heritage can't be cleanly re-entered mid-pipeline. The FAITHFUL mechanism is Ghidra's genuine ITERATING MAINLOOP (heritage↔rules↔deadcode restart-to-fixpoint) — the mainloop-repeat rock (backlog #8) — NOT a bolt-on re-heritage. The memory's "FIX = re-heritage after conversion" (S1-landed section below) was a HYPOTHESIS; this Phase-1 overturns it.

**PART 2 (stack spacebase branch) — needs NEW machinery (boundable).** Ghidra `correctSpacebase` (ruleaction.cc:4173): `if(!vn->isSpacebase()) return 0` → const=ram-global(S1) / else `getSpaceBySpacebase(RSP_addr,size)` + `assoc->getContain()==loadspace`. `vnSpacebase` (:4194) = RSP-input OR `INT_ADD(RSP_input,const)`. mosura HAS: `stack` space (SpaceKind::Spacebase, delay 1), SPACEBASE varnode flag (0x20000)+`is_spacebase()` w/ consumers (ptrarith/nzmask/infertypes/rules.rs:4556 `is_spacebase()&&is_input()`). MISSING: the flag is NEVER SET on any varnode (grep: only readers); NO `getSpaceBySpacebase`; RSP not registered as stack spacebase. So the stack branch can't fire until an ActionSpacebase-style registration marks the RSP INPUT `isSpacebase()` + adds the reg→space lookup. Meaty but bounded — and useless without part-1 re-versioning (same unversioned/unrefined regression, now across ALL stack fixtures).

**PART 3 (cancel stackvars) — mass-regression risk + rests on 1&2.** `stackvars::recover_stack` (stackvars.rs:122) is ONE pre-pool forward symbolic pass INTERLEAVING (a) the STORE/LOAD→stack-slot COPY conversion [`new_output`/`new_varnode` into `stack` space at the RSP-offset] = the adaptation to cancel, with (b) RSP-offset symbolic tracking + `call_push_restores` push/pop neutralization = the orthogonal SP-tracking to KEEP (≈ ActionSpacebase/StackPtrFlow). Canceling (a) makes stack STORE/LOAD survive to the pool — handled ONLY if part-2's stack branch exists AND part-1 re-versions. impliedfield (0.921, post cross-block-CSE) RELIES on stackvars stack-forward → cancel regresses it unless the replacement fully works. stackstring (0.794) also needs LaneDivide reactivation (task #6) at Ghidra's stackstall slot, which is blocked on this same migration.

**RECOMMENDATION (sent lead): HOLD all of S2.** The whole stack track is gated on the mainloop-repeat foundation (part 1); the naive re-heritage the memory assumed is verified-false. Keep S1 (revisit −0.021 = cited bounded cost of the versioning gap). Options: (A) take mainloop-repeat as its own foundational rock (unblocks S2 parts 1-3 + condconst-iterate + others), then S2 on top; (B) hold S2, pick a non-mainloop-blocked rock (nan 0.560=#11 F4c-2 CFG; floatconv 0.596=SVF narrowing; loopcomment 0.726). S2 has poor ROI until mainloop-repeat exists.

## ✅ S1 LANDED 2026-07-10 (p6b1) — master `cf14470` (verified: tree clean, suite 377/0, corpus 0.9168/56)
Lead GO'd S1 after a timeboxed revisit-snip check. Committed rules.rs (RuleLoadVarnode + RuleStoreVarnode, const-offset ram-global branch, +3 unit tests) + pipeline.rs (wired in ptrarith_pool after RulePtrArith = Ghidra actprop2 order coreaction.cc:5666-9) + coverage.md (2 rows PARTIAL + revisit citation). Delta EXACTLY as premise-verified: longdouble .783→.909, switchmulti .564→.628, revisit .654→.633 (−.021 CITED), avg 0.9140→0.9168 (+.0028), nothing new <.70.
**REVISIT-SNIP CHECK OUTCOME (lead-requested, DEEPER not bounded):** the merge-snip is FAITHFUL; revisit −.021 is the UPSTREAM value-versioning gap — the pool-time LOAD/STORE→COPY creates UNVERSIONED ram-varnodes (heritage ran to completion before the pools; Ghidra runs the rule in the re-heritaging mainloop). revisit IR: both reads (`u=COPY r0x100074`) + both stores (`r0x100074=COPY ...`) reference the SAME unversioned r0x100074, NO MULTIEQUAL read→store link → r0x100074 spans the whole fn → cover crosses store-defs → correct snapshot `iVar1=iRam; iRam=iVar1+10`. A snip-guard would non-faithfully paper over it. FIX = re-heritage after conversion → folds into S2 (same class as guardLoads-versioning). NOT a merge-snip refinement.
**NEXT = S2 (stack spacebase branch, HIGH RISK, the restructure) — scope AFTER S1, likely fresh budget.** vnSpacebase/correctSpacebase (RSP+const) + cancel pre-pool stackvars STORE/LOAD→stack-COPY + heritage guardLoads versioning (the re-heritage that ALSO recovers revisit) + KEEP orthogonal SP-tracking. Unblocks stackstring + LaneDivide reactivation. S3 (placeholder/resolveSpacebaseRelative) deferred.

## ✅ PHASE-1 COMPLETE 2026-07-10 (p6b1, base `c73a074`, all probes REVERTED → tree clean) — mechanism grounded + ram-global premise VERIFIED net-positive. Report sent lead, WAIT for stage gate.
Lead GO'd task #7 to me (warm from the triage). Phase-1 read-only, premise-first (P6 method).

**MECHANISM (line-cited, ruleaction.cc):** `RuleLoadVarnode::applyOp` (:4277) + `RuleStoreVarnode::applyOp` (:4319). Both call `checkSpacebase` (:4236) → `vnSpacebase` (:4194) → `correctSpacebase` (:4173). LOAD/STORE whose pointer is (a) a BARE CONSTANT or (b) `spacebase_reg [+ const]` → rewrite to a COPY of/into a direct varnode `newVarnode(size, space, offoff)` at that address (opSetOpcode COPY, remove ptr/space inputs). STORE also `setStackStore` + `markNotMapped` if StoreUnmapped. Placeholder trigger is LOAD-only: `if refvn->isSpacebasePlaceholder() → resolveSpacebaseRelative` (fspec.cc:4870) = the SP-across-call subsystem, SEPARABLE (defer to S3).

**ONE MODEL SUBSUMES BOTH (confirmed):** `checkSpacebase` — `offvn->isConstant()` branch returns the load-space directly = **RAM-GLOBAL** case (`LOAD/STORE #space #constaddr`); else `vnSpacebase`/`correctSpacebase` recognizes the stackpointer reg (+const) = **STACK** case. Same function, same rule pair. mosura decodes the LOAD/STORE space as `SpaceId(input0.loc.offset)` (heritage.rs:789).

**PREMISE VERIFIED — ram-global branch (throwaway probe `RuleLoadVarnodeProbe`/`RuleStoreVarnodeProbe`, const-offset branch only, env `MOSURA_SB`, wired in oppool, reverted):** revisit `*0x100074`→`iRam0000000000100074` and `pRam..100060`→`xRam..100060` — naming UNIFIES (visually confirmed). ★ KEY RISK RESOLVED: the pool-time LOAD→COPY(ram-varnode) conversion NAMES CORRECTLY with NO heritage re-pass (printc names ram varnodes address-based). CORPUS (all 60): **longdouble 0.783→0.909 (+.126), switchmulti 0.564→0.628 (+.064), revisit 0.654→0.633 (−.021 WASH), avg 0.9140→0.9168 (+.0028), 56/60, NOTHING new <.70, no other fixture touched, no stackvars/heritage code touched.** revisit −.021 = the merge-snip now over-snapshots the newly-addrtied ram-global reads (`iVar1=iRam; iRam=iVar1+10` vs Ghidra `iRam=iRam+10`) — a SECONDARY merge/void-recovery interaction, not a naming failure.

**STAGED PLAN (JumpBasic-style, gated):**
- **S1 = RAM-GLOBAL const branch (LOW RISK, net-positive mover, premise-verified above).** Port `checkSpacebase` const-offset branch + RuleLoadVarnode/RuleStoreVarnode const conversion; wire in oppool. Does NOT touch stackvars/heritage. Gate the revisit −.021 (merge-snip snapshot interaction — tune or accept). Broad naming win (longdouble/switchmulti). DO FIRST.
- **S2 = STACK spacebase branch (HIGH RISK, the restructure).** correctSpacebase/vnSpacebase (RSP-input + const; check SpaceManager already registers RSP-spacebase / need ActionSpacebase) + CANCEL mosura's pre-pool stackvars STORE/LOAD→stack-COPY adaptation + heritage guardLoads versioning (heritage.cc:1570, the DANGER ZONE = partialmerge-class value correctness). Unblocks stackstring + LaneDivide reactivation. KEEP orthogonal SP-tracking (symbolic_value RSP+const normalization + call_push_restores ≈ ActionSpacebase/StackPtrFlow — port separately).
- **S3 = placeholder + resolveSpacebaseRelative (DEFER).** SP-across-call; only if a fixture needs it.

**RISK MAP:** S1 low — (a) revisit merge-snip over-snapshot (tune at gate); (b) pool-created ram-varnode not re-heritaged → naming OK (verified), value-versioning-across-store may be imperfect (watch, but revisit values looked right). S2 high (sb2's map still valid): (1) heritage guardLoads load-before-store VERSIONING = silent value corruption, highest; (2) canceling stackvars too aggressively → mass regression; (3) pool/heritage convergence (restart-then-pool vs mainloop-repeat — may need a heritage pass after conversion); (4) setStackStore/markNotMapped → naming/typing; (5) impliedfield relies on stackvars stack-forward — preserve.

## ⭐ 2026-07-10 (p6b1) — POST-P6 TRIAGE RECOMMENDS THIS AS THE NEXT ROCK; scope is BROADER than stack (also RAM globals). Report sent lead, awaiting pick-gate.
After P6 landed (master `c73a074`, corpus 0.9140/56), triaged the 7 worst fixtures read-only. The low end collapses onto TWO subsystems; spacebase RuleLoadVarnode/RuleStoreVarnode is the recommended most-tractable-high-leverage pick (bounded rule pair vs task#9 SubVariableFlow's known Stage-3 net-regression). **KEY SCOPE EXPANSION: the same RuleLoadVarnode/StoreVarnode mechanism resolves RAM-GLOBAL constant-address LOAD/STOREs, not just stack** — mosura renders `LOAD/STORE #0xADDR` (ram) as `*0xADDR` where Ghidra names the global `iRam/fRam/xRam<addr>`. Proof: revisit's IR carries BOTH `LOAD/STORE #0x100074` (→`*0x100074`) AND ram-varnode `r0x100074:2` (→`iRam...100074`) for the SAME global; Ghidra unifies them. So this rock's leverage spans: global naming — revisit 0.654 / switchmulti 0.564 / longdouble 0.783 — PLUS stack ordering (stackstring 0.794, impliedfield 0.733) PLUS the LaneDivide reactivation unblock (task#6, moves stack-resolve post-pool to Ghidra's stackstall slot). **CONFIRMED mosura has NO RuleLoadVarnode/RuleStoreVarnode (grep) — genuinely UNBUILT.** BOARD-LABEL TRAP: the board's "task #1 COMPLETE" is the merge-phase bank (`9c1a20c`), a DIFFERENT thing; the spacebase forwarding here is still open. The OTHER low-end subsystem = task#9 SubVariableFlow / partial-register 16-byte-XMM+sign-ext-CONCAT narrowing (floatconv 0.596, floatcast 0.804, switchloop 0.790, revisit CONCAT22). Singletons: nan 0.560 (task#11 F4c-2 deferred CFG), switchloop DUPLICATE-statement structuring bug (`iVar1=2; iVar1=2;` — separate self-contained defect, possible quick win). Recommend a FRESH full-budget run for the restructure (replace pre-pool stackvars with in-pool spacebase forwarding), gated per-stage.

Task #1 = the "spacebase-placeholder rock." Owner sb1, in_progress. Base HEAD `28d07c2`,
suite 344/0, corpus avg 0.8905, impliedfield 0.733 (biggest below-baseline fixture).

GOAL: Ghidra forwards STORE→LOAD through the stack IN-POOL via RuleLoadVarnode/RuleStoreVarnode
over the spacebase-placeholder model. mosura instead resolves stack spill/reload PRE-POOL in its
own stackvars pass (a non-Ghidra adaptation → cancel per no-adaptation-grandfathered). See
[[printc-structuring-adaptation-conflicts]] (third class member, IR-side).

## ✅ TASK #1 COMPLETE — merge-phase bank LANDED master `9c1a20c` (2026-07-10, sb5)
The whole merge-phase arc is DONE: B-i ADDRTIED `61147e1` → op_destroy `91ddcf7` → iop `e97e4fe`/`7760c3b`
→ snip wired `f3eff2a` → **bank `9c1a20c`** (guard_returns persist COPY + B-iii merge module). Lead GO'd
land-as-is (regressions are the faithful port exposing non-faithful P6 return-recovery — "only non-Ghidra
code is in question"; the SAME persist COPY that banks partialmerge holds the global to end on a void fn, so
you can't separate the bank from the void-exposure without making guard_returns un-faithful). Post-land
re-verified on master: suite 354/0, corpus 0.8976, partialmerge 0.970 — all reproduce, tree clean.
2 REGRESSIONS cited as TRIPWIRES for **task #4 P6** (switchhide 0.940→0.918, noforloop_globcall 0.857→0.810):
guard_returns persist COPY held-to-end on a void fn → mosura return-recovery renders the held global as a
return value where Ghidra's active-output trials detect void. B-ii multiret/sbyte tripwire RESOLVED (named
temps, no self-assigns). partialmerge residual `(int4)xRam` cast = VariablePiece P4/P8 debt. Build findings
(the mechanism chain) preserved in the section below — reusable for P6 and any future merge-phase work.
NEXT ROCK = task #4 P6 (3 stacked consumers: condconst int4*-residual + LaneDivide 4-byte-XMM + these 2 void
regressions). Do NOT start new work post-land: lane2 inert-lands task #6 on top; lead merges lead-side → 1 agent.

## B-iii BUILT + MEASURED — partialmerge BANKED (2026-07-10, sb5) [LANDED as `9c1a20c`, above]
Base `f3eff2a`. Landed heritage.rs
(guard_returns persist COPY + wire), op.rs (RETURN_COPY 0x200 + is/mark), rules.rs (RulePropagateCopy
is_return_copy), merge.rs (merge_addrtied + merge_copy + merge_test_basic/required + high_props + 3 unit
tests), printc.rs (high_ram_off + 5 is_explicit/emission arms), docs/coverage.md (2 rows).
**RESULT: corpus 0.8936→0.8976 (+0.0040), 55/60≥0.70 (was 54), suite 354/0 (351+3 merge tests). partialmerge
0.786→0.970 (THE BANK — post-store re-read fixed: `iVar1 = xRam; xRam = param_1; return iVar1+10`;
only residual = missing `(int4)` cast = VariablePiece/P4-P8 debt).** Movers: +partialmerge .184,
+revisit .058, +noforloop_iterused .057, +condmulti .013; −noforloop_globcall .047, −switchhide .022.
NOTHING newly <0.70.
STEP-1 VERIFY (both lead risks CLEARED, instrument-first): (a) NO double-insert — the 2 guard_returns
firings = AliasChecker probe clone (pipeline.rs:59) + real heritage (identical vids ⇒ clone); new_addrs/
intersect==2 gate stops cross-pass re-guard (same as guard_calls). (b) COPY width = 8 = store version;
guarded ram Loc IS 8-byte, terminal COPY input renames to store-ver (`r0x100670:8=COPY r0x100670:8`).
KEY BUILD FINDINGS (mechanism chain, all faithful, each needed):
1. merge_addrtied gate = `!is_free` NOT cover-bearing (Ghidra unifyAddress) — the addrForce terminal-out has
   NO reader/cover but must join glob1 else the terminal COPY stays cross-high → spurious `xRam=xRam`.
2. same-high COPY HIDE in printc emission (markInternalCopies opMarkNonPrinting) — hides the terminal COPY.
3. addrtied→explicit in is_explicit (baseExplicit "pointers may reference it") — WITHOUT it, guard_returns'
   terminal makes a global STORE single-use→implied→VANISHES (displayformat/namespace/floatprint stores gone).
4. high_ram_off (rep→ram addr, ram analogue of high_stack_off) — a value merge_copy unifies INTO a global's
   high is named/materialized by that address (`iRam.. = param_1+1`); EXCLUDE reps with a stack member else a
   stack local init'd from a global (pointerrel fStack_18, switchhide iStack_18) mis-names as fRam/iRam.
5. cross-high COPY arm gated on **is_persist** input (NOT is_addrtied) — persist=the partialmerge snapshot;
   addrtied caught escaped-stack snapshots (noforloop_alias `uVar1=uStack_14` spurious). register COPY inlined.
6. merge_test_required stack-tied: a `stack` member counts tied-to-addr (Ghidra maps stack locals addrtied;
   mosura flags only escaped) so merge_copy won't merge a stack local into a diff-addr global. Unexercised on
   corpus (pointerrel/switchhide over-merge was merge_MARKERS via a phi, fixed by #4's stack-exclusion) but
   faithful + unit-tested.
2 REGRESSIONS = BOTH P6 void-return (→task #4): guard_returns persist COPY for a VOID fn + mosura return-recovery
treats the held/leftover global (RAX) as a return value where Ghidra detects void. noforloop_globcall (lead
expected CLEAR — global-STORE handling IS correct/banked, but returns spurious `iVar1=iRam601030`; also
for-vs-while + missing call-arg). switchhide = stack-canary epilogue returned as `iVar2` + `in_FS_OFFSET`
naming + call-arg. NOT the merge module — the guard_returns→P6 interaction. NEXT: report sent lead, WAIT for
landing go; on go commit (NEVER git add -A; the 3 WIP files + merge.rs/printc.rs/coverage.md). union_datatype
(PIECE debt) + heapstring/elseif/noforloop_alias/pointerrel were transient over-fires all FIXED by the gates above.

## B-iii COVER-LIVENESS ANSWERED — mechanism = Heritage::guardReturns persist branch (2026-07-09, sb4)
Base `f3eff2a`, suite 351/0, corpus 0.8936, partialmerge 0.786. READ-ONLY scope of "how does Ghidra
cover the addrtied store-version that has no explicit reader?" — ANSWERED (instrument-first, oracle IR):
**NOT a cover-model change (updateInternalCover/cover.cc/markInternalCopies self-COPY were the brief's
candidates — all WRONG). It is UPSTREAM in HERITAGE: `Heritage::guardReturns` (heritage.cc:1676-1691),
the `persist` branch, inserts a terminal COPY before every RETURN for a persistent (global) range:**
`copyop = COPY; out@(addr,size) [setAddrForce + markReturnCopy]; in@(addr,size); opInsertBefore(RETURN)`.
After SSA rename that COPY's INPUT picks up the store version → gives it a real READER → mosura's EXISTING
cover_of covers it automatically (no cover.rs surgery). Confirmed in oracle final IR: partialmerge has
`r0x00100670(0x1006b9:28) = r0x00100670(0x1006ad:2)` @0x1006b9 = exactly this COPY. So glob1 = {input-ver
+ store-ver + terminal-out-ver} all addrtied → merge_addrtied unifies → WHOLE high w/ spanning cover →
snapshot u interferes → merge_copy declines → markInternalCopies makes u explicit → banks partialmerge.
KEY DETAILS: (1) persist flag is computed FRESH at guard time via queryProperties (heritage.cc:1191), NOT
a pre-set varnode flag → guard_returns does NOT depend on ActionMarkAddrTied timing; mosura determines it
by SPACE (ram→persist, scope.rs:114 / varnodeprops.rs mark_addrtied logic). (2) `return_copy` op flag is
LOAD-BEARING: RulePropagateCopy bails on it (ruleaction.cc:3933) — without it, propagatecopy replaces the
terminal COPY's input (store-ver) with RDI (store's source) → strips store-ver's reader → reverts the bug.
mosura's RulePropagateCopy ALREADY anticipates this (rules.rs:648, uses `code()==Return` as a stand-in +
comment "no globals-holding markReturnCopy COPY yet"). NEED: add RETURN_COPY op flag (op.rs flags, next
free 0x200) + is_return_copy/mark_return_copy + flip that guard to is_return_copy(). (3) heritage.cc:329
uses isReturnCopy as "evidence of previous heritage in this range" (re-entry guard) — assess for mosura's
per-pass collect (likely non-issue single-pass; verify multi-pass). (4) SIZE: terminal COPY is 8-byte
(store-ver width) — verify mosura's heritage Loc for glob1 is the 8-byte range so the input renames to the
store-ver not a partial. (5) DISTINCT from task #3: task #3 = guardReturns' ACTIVE-OUTPUT branch (lines
1658-1675, return-value trials/characterizeAsOutput/return-width) = P6; partialmerge needs ONLY the persist
branch (1676-1691). They don't collide.
COST VERDICT = BOUNDED, not a subsystem cascade. guard_returns persist branch ≈15 lines reusing existing
primitives (new_op/new_varnode/new_output/opSetOpcode/opInsertBefore/set_addr_force — all used by
guard_calls) + 1 op flag + flip 1 guard + wire 1 line into heritage_spaces guard loop (after guard_calls,
gated ram/persist). Then RE-APPLY the already-BUILT B-iii module (merge_copy + merge_addrtied +
markInternalCopies cross-high arm + high_of, per FRESH-RUN TURNKEY §). MUST build+measure guard_returns
TOGETHER with the B-iii module (guard_returns alone adds the terminal COPY with no markInternalCopies to
absorb it → would regress). All gated (MOVER).
8-FIXTURE OVER-FIRE = a MIX, NOT all the same missing-whole-high cause (oracle --c categorization):
- noforloop_globcall: writes global iRam601030 in a loop (void, not returned) = SAME cause → guard_returns
  gives it a cover (persist branch fires on any RETURN even for a void fn).
- union_datatype: union field stores via typed ptrs = the OMITTED markInternalCopies PIECE/SUBPIECE arms
  (P4/P8 debt, no VariablePiece/TypePartialStruct) = SEPARATE cause, NOT guard_returns.
- multiret + sbyte: empty oracle output (flow-override, oracle-UNCAPTURABLE) = the known partial-overlap
  snip residual, tracked separately (multiret verify-at-B-iii tripwire).
- elseif/heapstring/noforloop_alias/ptrtoarray: no global-return; register/stack cross-high COPYs =
  incomplete merge_copy / maybe MergeAdjacent (merge.cc:983) — need per-fixture instrument AFTER the gated
  build to confirm which markInternalCopies arm fires. Prediction: most merge same-high once glob1 is whole
  + merge_copy complete; genuine residuals = union_datatype (PIECE arm) + multiret/sbyte (tracked).
NEXT (lead gates): on GO, build guard_returns persist branch + return_copy flag → re-apply B-iii module →
wire → full per-fixture delta gate (partialmerge to oracle shape = target mover; 8-list must clear or be
individually explained; multiret verification; nothing new <0.70; suite green). REPORTED to lead, WAITING.

PHASE 1 = READ-ONLY SCOPING; report to lead + WAIT before any code. Four parts: (1) ground
Ghidra's model line-cited; (2) instrument impliedfield + stack-heavy fixtures IR divergence;
(3) map mosura stackvars overlap-vs-orthogonal; (4) staging + risk map.

Later same infra: RuleLeftRight (needs op_unset_input/output + register-piece varnode creation).

## PHASE 1 FINDINGS (2026-07-09, instrument-first) — PREMISE OVERTURNED

**The lead's/memory's premise "spacebase model fixes impliedfield" does NOT hold.** Proven by
IR dumps + a local probe. impliedfield's real root cause is a CROSS-BLOCK CSE gap, unrelated to
the spacebase model.

Evidence chain:
- mosura's `stackvars::recover_stack` ALREADY forwards the spill: the float reload resolves to
  block-0's subpiece; no STORE/LOAD survive in final IR. (`--prestack` dump is misleading — it
  early-returns because blocks aren't built there; instrument via full pipeline / heritage-only probe.)
- Both Ghidra and mosura reach the identical expression `SUBPIECE(RDI>>0x20,0)` for the high dword.
  Ghidra computes it ONCE at register-piece location `RDI+4:4` (single SSA def in dominator block 0,
  used by BOTH branches). mosura computes it TWICE — block 0 (feeds float) + block 2 (feeds int mult),
  two unshared uniques → no shared explicit var → union field never prints.
- trace-diff impliedfield: subright ghidra=1x @0x1006aa (shared def) vs mosura=2x @per-use;
  subnormal ghidra=1x vs mosura=2x. Symptom, not cause: they fire per-use BECAUSE the value isn't shared.
- Post-heritage probe (throwaway sbprobe.rs, deleted): mosura keeps the shift-value RAX:8 as ONE
  shared def; subpieces are per-use. After 1 rule-pool pass both blocks hold `SUBPIECE(r0x38,4)`
  (=RDI+4:4) — identical, RDI is common input. They should CSE. They don't. Then RuleSubNormal
  re-expands EACH back to shift-form (Ghidra re-expands the ONE shared varnode once).

ROOT CAUSE (definitive): **mosura's `RuleSelectCse` (rules.rs ~1157) is SAME-BLOCK ONLY** — hard
guard `data.op(other).parent != Some(parent) → continue`. Ghidra's `RuleSelectCse` →
`cseEliminateList`→`cseElimination` (funcdata_op.cc:1356) is CROSS-BLOCK: `findCommonBlock` (common
dominator); if one op's block dominates the other, keep the dominating op + `totalReplace` the other;
if neither dominates, build a new op at the common-dominator's stop. mosura ports only the same-block branch.

PROBE (local, reverted): remove the same-block guard; when parents differ, `dominator::compute` +
if one `dominates` the other, keep the dominating op / repoint the dominated (skip neither-dominates).
RESULT: impliedfield 0.733→**0.921** (+0.188), corpus avg 0.8905→**0.8936** (+0.0031, ENTIRELY from
impliedfield → no other-fixture regression), suite 344/0. The shared `fVar1` explicit var forms.
Residual impliedfield gap (0.921 not 1.0) = missing casts + `val.u.myfloat` union-field naming =
downstream P4-type/prototype application (the fixture's `parse line getvalue(packstruct,int4)` proto),
NOT the CSE and NOT the spacebase model.

## TRACK B — B0/B3 INSTRUMENT (2026-07-09, sb2) — PREMISE OVERTURNED AGAIN (partialmerge ≠ spacebase)
Base HEAD `02a7840`, suite 346/0, corpus avg 0.8936. Read-only probe (throwaway `zz_sbprobe.rs`,
deleted; tree clean) dumped mosura IR (raw/heritage/final/C) + oracle `--ir` + `capture_trace --trace`
for partialmerge **readpartial** (the ONLY scored fn — corpus uses chunk[0] offset 0x1006a7).

**partialmerge readpartial is NOT a spacebase/LOAD case.** The const-addr access (`mov ebx,[rip+glob1]`
+ `mov [rip+glob1],rdi`) lifts to a DIRECT ram-varnode COPY in BOTH mosura and Ghidra — NO LOAD/STORE
op ever exists (raw IR identical). So RuleLoadVarnode/guardLoads are irrelevant here. mosura and Ghidra
then produce **byte-identical IR** all the way through `EBX = r0x100670:4(i) + #0xa` (input-version read
of the low dword, pre-store). Chain (faithful in both): heritage makes the pre-store read `SUBPIECE(
r0x100670:8[input version],0)` (rename gives op0 the input ver since it precedes the store at 0x1006ad)
→ `subvar_subpiece`/SubvariableFlow (rules.rs:3781) narrows it to `r0x100670:4(i)` → `propagatecopy`
(RulePropagateCopy rules.rs:629) folds it into the ADD. All match Ghidra trace DEBUG 39/40/44.

**THE SOLE DIVERGENCE = mosura lacks Ghidra's `ActionMergeRequired` snip.** Ghidra trace DEBUG 49
`mergerequired`: inserts `u0x10000008:4 = COPY r0x00100670:4(i)` and repoints the ADD to the unique —
because the addrtied input-version read's Cover crosses the store's same-address version. That snapshot
COPY is what prints `a_simple = glob1.a; return a_simple + 10`. mosura never snips → ADD keeps reading
addrtied ram → printc emits `xRam...=param_1; return iRam... + 10` (post-store global re-read = the bug).

Ghidra mechanism (line-cited): `ActionMergeRequired` (coreaction.hh:362, added coreaction.cc:5718) →
`Merge::mergeAddrTied` (merge.cc:609, gated `flags & addrtied`) → `unifyAddress` (:581) →
`eliminateIntersect` (:489, per-read Cover vs same-addr `blocksort`, `containVarnodeDef`+
`characterizeOverlap`+`partialCopyShadow`) → `snipReads` (:443, `allocateCopyTrim` at vn's def point;
input→opInsertBegin(block0)). mosura HAS the detection half: `merge::merge_same_storage` (merge.rs:114)
+ Cover (cover.rs) + `classes_interfere` already FIND this intersection — but only DECLINE to merge; no
snip COPY is inserted. Also mosura's `merge::merge` is a read-only naming pass called from printc.rs:19
/ infertypes.rs:35 — NOT a graph-mutating mainloop action. Porting the snip = making merge (or a new
ActionMergeRequired) MUTATE the graph (insert COPY-into-unique) BEFORE printc, then re-run deadcode.
Open design Qs for the port: (a) is global ram marked `addrtied` before merge runs? ADDRTIED set only
in scope.rs:115 (recover_scope, print-time) — mergeAddrTied's gate needs it earlier; (b) Cover/def-point
insertion + descend repoint must land pre-print. This is the Merge subsystem, ORTHOGONAL to spacebase.

IMPLICATION (parallels track-A): partialmerge's 0.786 correctness bug is fixed by porting
`Merge::mergeAddrTied`/`eliminateIntersect`/`snipReads` (+ ActionMergeRequired placement), NOT the
spacebase model. stackstring (0.794, the OTHER track-B target) may still be a real guardStores/spacebase
case (memory notes: "stores to stack slots whose addr escapes to a call") — needs its own instrument
before assuming. Reported to lead; WAITING for re-scope decision. Old B1-B5 staging below is now suspect
for partialmerge (kept for the stackstring/spacebase question).

## TRACK B — B-i LANDED (2026-07-09, sb3) — byte-identical, NOT the predicted mover
Base `345d362` (suite 348/0, corpus 0.8936). B-i committed `61147e1` (suite 350/0, corpus 0.8936
BYTE-IDENTICAL 62/62 exit 0 — self-approved per gate-byte-identical-only). New module
`varnodeprops.rs` (`mark_addrtied` + `ActionMarkAddrTied`), wired in pipeline.rs after
ActionResolveCalls, before the first default_rule_pool. Determination = ram→MAPPED|ADDRTIED|PERSIST,
stack→MAPPED|ADDRTIED iff `alias_boundary.is_some_and(|b| off>=b)` (mosura's existing
AliasChecker::hasLocalAlias boundary, the SAME test heritage.rs:837/guard_calls uses — the turnkey
said "offset ∈ aliased_stack_offsets" but the boundary model is the faithful `hasLocalAlias` and is
what mosura already uses; `alias_boundary` is already stored on Funcdata post-heritage, perfect
timing), else untouched. 2 unit tests.
GROUNDED against Ghidra: setVarnodeProperties (funcdata_varnode.cc:25) → Scope::queryProperties
(database.cc:1263: finalscope!=0 ⇒ mapped|addrtied, +persist if isGlobal) at CREATION; stack cleared
by ActionRestructureVarnode/syncVarnodesWithSymbols (funcdata_varnode.cc:938,976) via
isUnmappedUnaliased (varmap.cc:494). mosura folds both into one post-heritage pass.
**KEY FINDING: byte-identical, NOT the "GATED MOVER" the turnkey/lead predicted.** The 5 dormant
guards it activates are inert or absorbed on the corpus: rules.rs:6855 (RuleSubRight addrtied),
condconst.rs:492/506 (addrtied phi), subvarflow.rs:363 (use_same_address addrtied), AND
subvarflow.rs:214 (is_persist guard — activated by PERSIST on ram globals; turnkey missed this 5th
guard). Flag VERIFIED reaching targets: partialmerge global r0x100670 marked 0x20c000 =
MAPPED|ADDRTIED|PERSIST (instrument, reverted). MAPPED has no consumers (inert). Reported to lead.
## FRESH-RUN TURNKEY — B-iii = bank partialmerge (2026-07-09, sb3 spent after 5-commit marathon)
BASE `f3eff2a`, suite 351/0, corpus 0.8936, tree CLEAN. Landed chain (all faithful): B-i `61147e1`
(ADDRTIED marking) → op_destroy `91ddcf7` → iop-1 `e97e4fe` → iop-2 `7760c3b` → B-ii `f3eff2a` (snip
WIRED, fires on partialmerge, all 60 scored byte-identical, multiret cited pre-B-iii residual).
GOAL: bank partialmerge to the ORACLE shape `iVar1 = xRam...100670; xRam...100670 = param_1; return
iVar1 + 10;` (currently flat `xRam...=param_1; return iRam...+10` = post-store re-read bug).
B-iii CODE (BUILT, faithful, unit-testable, REVERTED — re-apply):
 (1) merge.rs `merge_copy` = Ghidra mergeOpcode(CPUI_COPY) merge.cc:326 (block order; union COPY in/out
     iff !classes_interfere; skip on intersect = Ghidra ignores merge() return :346) + `merge_test_basic`
     (hasCover; implied/protopartial/spacebase not modeled) + `merge_test_required` (mergeTestRequired
     merge.cc subset: addrtied-diff-addr / input+persist / input+addrtied guards; typelock/protopartial/
     extraout omitted). (2) merge.rs `merge_addrtied` = union addrtied cover-bearing varnodes by
     (space,offset) any size. (3) printc.rs is_explicit: cross-high COPY (high_of[out]!=high_of[in],
     non-const in) → explicit = markInternalCopies COPY arm (merge.cc:1461); + `high_of: Vec<u32>` frozen
     union-find rep field (immutable view for &self). PIECE/SUBPIECE arms of markInternalCopies absent
     (no VariablePiece / TypePartialStruct — P4/P8 debt; note it).
**BLOCKER (why the above is necessary-but-NOT-sufficient):** partialmerge's addrtied global glob1 is NOT
one COVERED HighVariable in mosura. ZZ_MA instrument: merge_addrtied group at 0x100670 = ONLY
[(id109,size4,addrtied)] — the 8-byte STORE version r0x100670:8 has NO readers (printer re-reads global
by NAME) → cover_of gives it empty cover → not in all_covers → merge_addrtied group size 1 → glob1 cover
tiny → snapshot u[0x1006a7..b4] doesn't interfere → merge_copy MERGES u→glob1 → u inlined → FLAT.
Ghidra glob1 spans ALL versions: oracle IR `r0x00100670 = r0x00100670(0x1006ad)` @0x1006b9 (store version
IS read/addrtied-materialized → covered). ⇒ **PREREQ = faithful mergeAddrTied + addrtied COVER-LIVENESS**
(addrtied writes kept live at their address / the store-version re-read materialized), a Merge/cover-model
stage. NEXT (scope read-only first, like the iop-link): ground variable.cc HighVariable::updateInternalCover
+ how Ghidra covers an addrtied write with no explicit reader (does markInternalCopies' `r=r(store)` COPY
create the reader? is it addrtied liveness in Cover?), then port. AFTER glob1 whole → re-apply (1)(2)(3) →
partialmerge banks + gate (full delta, multiret verification: named temps=resolve citation / spurious=new
task, nothing new <0.70). PROBE DELTA (merge_copy+CopyMarker w/o whole glob1): over-fire 25→8 fixtures
[elseif heapstring multiret noforloop_alias noforloop_globcall ptrtoarray sbyte union_datatype], partialmerge
flat → NOT landable. mergeTestRequired FULLY READ (merge.cc) — NO guard forbids the u-merge, purely cover.

## TRACK B — B-iii BUILT: MergeCopy+CopyMarker NECESSARY but NOT SUFFICIENT (2026-07-09, sb3)
Built merge_copy + merge_addrtied (merge.rs) + markInternalCopies cross-high-COPY rule + high_of
(printc.rs). ALL REVERTED to clean f3eff2a (mover, partialmerge did NOT bank). **BLOCKER (confirmed by
instrument): partialmerge's addrtied global glob1 is NOT one covered HighVariable in mosura.** merge_copy
correctly skips the snapshot ONLY IF glob1's cover spans the store — but mosura's glob1 = just the 4-byte
input `id=109` (ZZ_MA: group at 0x100670 = [(109,4,true)] ONLY). The 8-byte STORE version `r0x100670:8`
has NO readers in mosura (printer re-reads the global by NAME) → no cover → merge_addrtied can't unify it
(group size 1). So glob1's cover is tiny → snapshot u [0x1006a7,0x1006b4] doesn't interfere it →
merge_copy MERGES u into glob1 → u inlined → partialmerge stays FLAT (buggy). In Ghidra glob1 spans ALL
versions (oracle IR: `r0x00100670 = r0x00100670(0x1006ad)` at 0x1006b9 — the store version IS read /
addrtied-materialized, giving it a cover). So B-iii needs FAITHFUL **mergeAddrTied + addrtied
cover-liveness** (the addrtied global's versions unified + covered) as a PREREQUISITE before merge_copy /
markInternalCopies can discriminate the snapshot. That's a Merge/cover-model fidelity stage BIGGER than
the scoped MergeCopy+CopyMarker. mergeTestRequired FULLY READ (merge.cc, no guard prevents u-merge — it's
purely the cover). merge_copy/markInternalCopies code is CORRECT+faithful (keep for re-use) but reverted.
Probe (merge_copy+CopyMarker, no full glob1): over-fire 25→8 fixtures (elseif/heapstring/multiret/
noforloop_alias/noforloop_globcall/ptrtoarray/sbyte/union_datatype), partialmerge flat. REPORTED to lead:
B-iii bank blocked on Merge/cover depth — natural checkpoint after the 5-commit chain. Base f3eff2a.

## TRACK B — B-iii GROUNDED: mechanism = MergeCopy+CopyMarker, NOT baseExplicit (2026-07-09, sb3)
Ground-truth (oracle partialmerge --c/--ir + probe): partialmerge needs the snapshot `u=COPY glob` to be
EXPLICIT (`iVar1 = xRam...; return iVar1+10`). **baseExplicit does NOT do this** — u is single-use →
baseExplicit returns desccount=1 → IMPLIED. mosura's is_explicit (printc.rs:177-235) ALREADY ports
baseExplicit's intent (input/call/phi/indirect→named, single-use→inline). **The real mechanism =
Ghidra's markInternalCopies (ActionCopyMarker, coreaction.cc:5729 / merge.cc:1444): a COPY between two
DIFFERENT HighVariables is a printed assignment (output named); same-high COPY → opMarkNonPrinting.**
Ghidra merge phase ORDER (coreaction.cc): 5718 MergeRequired(snip, DONE B-ii) → 5719 MarkExplicit
(baseExplicit) → 5722 **MergeCopy** (`Merge::mergeOpcode(CPUI_COPY)`, merge.cc:326: merge each COPY's
in/out highs iff covers don't interfere) → 5726 MergeAdjacent → 5729 CopyMarker(markInternalCopies).
PROBE (cross-high-COPY→explicit in is_explicit, high_of precompute, REVERTED): FIXED partialmerge's
sequence point BUT over-fired ~25 fixtures + a spurious `iVar2=iVar1+10;return iVar2` — because mosura
LACKS MergeCopy, so redundant return/register COPYs (`EBX=COPY(add_result)`) stay cross-high. With
MergeCopy first, those merge same-high (covers don't interfere) → hidden; only the snapshot (glob addrtied
→ in the global's high whose cover INTERFERES u, which is WHY the snip existed → can't merge) stays
cross-high → explicit. **FAITHFUL B-iii = port `mergeOpcode(COPY)` into merge.rs's merge() (mosura HAS
classes_interfere+all_covers primitives; add merge_copy after merge_same_storage) + markInternalCopies
cross-high-COPY rule in is_explicit (my probe, now correctly scoped) + high_of precompute. Maybe
MergeAdjacent (merge.cc:983) too.** = a MERGE-SUBSYSTEM stage (2-3 actions), bigger than the lead's
"ActionMarkExplicit term-count" framing but tractable + faithful. Reported to lead for scope confirm.
coverage.md MergeRequired row lists MergeCopy/MergeAdjacent/CopyMarker as not-yet-ported. Base f3eff2a.

## TRACK B — B-ii LANDED + B-iii NEXT (2026-07-09, sb3)
**B-ii LANDED `f3eff2a`** (lead GO'd fallback-b with the multiret verify-commitment tripwire). Snip gate
is_addrtied + wired ActionMergeRequired after condnegate-deadcode + 2nd ActionMarkAddrTied re-mark before
it + coverage.md (ActionVarnodeProps 2nd-mark/addrtied-at-creation-backlog note; MergeRequired row flipped
WIRED with the multiret VERIFY-at-B-iii tripwire). POST-LAND RE-VERIFIED on master: suite 351/0, corpus
avg 0.8936 (54/60), all 60 SCORED + partialmerge BYTE-IDENTICAL (only unscored multiret differs),
partialmerge snip FIRES (instrument reverted: `vn=(sp1,0x100670,4) read=IntAdd` = the narrowed global
input read crossing the store). Tree clean at f3eff2a.
Landed chain this session: B-i `61147e1` → op_destroy `91ddcf7` → iop-1 `e97e4fe` → iop-2 `7760c3b` →
B-ii `f3eff2a`. All faithful, all byte-identical-on-scored except op_destroy/B-i (byte-identical everywhere).
**B-iii NEXT (lead GO'd): faithful ActionMarkExplicit** — the real term-count/depth heuristics (coreaction.cc
:5719 right after mergeRequired), the WHOLE action, NOT a printc "don't-inline-addrtied-COPY" adaptation.
Ground its relationship to printc.rs:217's single descend-count explicitness heuristic (the faithful action
subsumes/coexists — determine which). = the partialmerge MOVER (banks the snapshot as a named temp).
Report: full corpus delta gate + the multiret VERIFICATION in the SAME report (named temps ⇒ resolved;
still-spurious ⇒ open dedicated multi-width-partial-overlap task). Base f3eff2a.

## TRACK B — iop-1/iop-2 LANDED + B-ii residual (2026-07-09, sb3)
LANDED both byte-identical (self-approved): **iop-1 `e97e4fe`** = `guarded_op: Option<OpId>` field on
PcodeOp (Ghidra iop, doc-cited newVarnodeIop + flag-XOR representation precedent) set at 3 prod INDIRECT
sites (new_indirect_op + heritage.rs:866/877) + `cover::op_index` helper (INDIRECT→guarded-op pos,
fallback own) + unit test; readers UNWIRED. **iop-2 `7760c3b`** = switched cover_to_read + cover_of +
mergesnip def_point to op_index. Byte-identical (naming path cover_of unaffected on corpus; snip path
dormant until B-ii). Suite 351/0.
**B-ii re-measured on iop base (uncommitted on 7760c3b, suite 351/0, instrument-free):** iop fix REDUCED
multiret over-fire (removed 2 self-assigns + the boundtype-1 MULTIEQUAL case became boundtype-2 as the
INDIRECTs correctly collapsed to the call position) BUT a RESIDUAL remains — all still at the aliased
multi-width slot -0x14. Two categories (ZZ_SNIP): (A) multiple INPUT varnodes at -0x14 of DIFFERENT
widths 1/2/4 (partial overlap overlaptype=1, def=None both, boundtype=1, read by the call INDIRECTs) —
partial_copy_shadow can't prove input-vs-input shadow (no defs; Ghidra findSubpieceShadow same); (B)
INDIRECT-def 2byte vs 1byte at the SAME call, boundtype=2 (post-iop), read by MULTIEQUAL@0x100030 — the
same-place ordering tiebreak snips one. **KEY: the residual is plausibly CORRECT Ghidra behavior** (both
match Ghidra's overlaptype-1/boundtype-2 logic) rendered as `xStack_14 = xStack_14` ONLY because of
pre-B-iii inlining (same reason partialmerge stays flat). multiret is UNSCORED + oracle-UNCAPTURABLE
(flow-override "Bytes at 0x100282 not mapped") so can't confirm directly — B-iii MarkExplicit is the
natural clarifier (renders snapshots as named temps). All 60 SCORED fixtures + partialmerge byte-identical;
partialmerge snip fires (wire live for B-iii). REPORTED to lead: recommend fallback (b) — land B-ii with
multiret residual cited on the coverage row + follow-up, proceed to B-iii which clarifies multiret.
B-ii uncommitted bits: mergesnip.rs (gate is_addrtied + doc + 2 test mark_addrtied) + pipeline.rs (2nd
ActionMarkAddrTied re-mark + ActionMergeRequired wire + deadcode). coverage.md notes still TODO (fold in
B-ii commit): ActionMergeRequired row + 2nd-mark once-pass approximation + addrtied-at-creation backlog +
multiret residual citation.

## TRACK B — iop-link SCOPE (2026-07-09, sb3) — lead chose (a), 2nd-mark ACCEPTED
Lead decided (a): ground+scope the iop-link port, report before building; (b)=land B-ii w/ multiret
limitation cited stays FALLBACK only if scope shows iop-link is disproportionate. Lead ACCEPTED the
second `.then(ActionMarkAddrTied)` before ActionMergeRequired for B-ii/B-iii as a documented once-pass
approximation (same family as pipeline-shape translations); **addrtied-at-creation (setVarnodeProperties
per varnode) = the faithful follow-up, LOGGED as backlog** — add to coverage note + this memory (DONE
here; coverage.md note folds into the B-ii commit).
**iop-link SCOPE (grounded read-only):** MINIMAL faithful shape = `guarded_op: Option<OpId>` FIELD on
PcodeOp (op.rs struct is 6 fields, clean add), set at INDIRECT creation from the already-in-scope causing
op. Faithful semantic equiv of Ghidra's `input(1)=newVarnodeIop(indeffect)` annotation varnode (Ghidra's
annotation is a serialization detail; semantic = "which op caused this INDIRECT"; representation choice
noted like the flag-XOR precedent). Ghidra reads it via `CoverBlock::getUIndex` (cover.cc): INDIRECT →
`getOpFromConst(getIn(1))->getSeqNum().getOrder()` = the guarded op's order.
CREATION sites (all have causing op): funcdata.rs `new_indirect_op(indeffect,...)`; heritage.rs:866/877
guard_calls (`call` in scope); recover.rs:521/568 are TEST-ONLY. = ~3 prod sites.
READERS to update (map INDIRECT→guarded-op index): cover.rs `cover_to_read` (SNIP-only) + `cover_of`
(→all_covers→merge.rs GENERAL naming) + mergesnip.rs `def_point`. All three duplicate the (block,idx)→
2i+1/2i+2 half-point logic; unify via a shared `op_index(f,op)` that returns the guarded-op idx for an
INDIRECT (fallback to own idx if the guarded op is dead/gone). MULTIEQUAL already special-cased (→pos 0).
BLAST/CASCADE: consume.rs iop comment = orthogonal (setIndirectSource consume-propagation, NOT cover;
my field doesn't touch consume — claim holds). deadcode/heritage don't read cover positions (cover is
merge-phase-late). **THE one cascade = cover_of feeds merge.rs read-only naming → applying the iop map
there is a separate NAMING mover beyond the snip; cover_to_read (snip) is isolated.** Ghidra's getUIndex
is GLOBAL so faithful = apply to ALL cover readers; recommend build the field + all readers + MEASURE the
combined corpus (snip fixes multiret; general-merge path likely byte-identical but gate it). = normal
gated stage (field+threading), NOT a heritage/deadcode cascade → build it (lead criterion 3).

## TRACK B — op_destroy ROOT FIX LANDED + B-ii 2 remaining issues (2026-07-09, sb3)
LANDED `91ddcf7` (on B-i `61147e1`): **op_destroy now frees the destroyed op's output** (clears
INPUT|INSERT|WRITTEN + def, = Ghidra destroyVarnode). Byte-IDENTICAL 62/62, suite 350/0, self-approved.
ROOT CAUSE of the enum-class over-fire: mosura's `Funcdata::op_destroy` (funcdata.rs) only nulled def +
cleared WRITTEN, LEFT INSERT set → destroyed outputs lingered as non-free ORPHANS (def=None, not input,
is_free()==false, ndesc=0). Ghidra's opDestroy calls destroyVarnode(getOut()) removing it. These orphans
are invisible to normal passes but the snip's `!is_free` gate treats them as live same-address varnodes.
INSTRUMENT (ZZ_SNIP tuples on enum): `vn=(sp4,0x0,8)def=None input=true` vs `vn2=(sp4,0x0,8)def=None`
(the orphan) boundtype=1 overlaptype=2 → spurious snip. ZZ_VN dump found id=253 (def=None,input=false,
free=false) = the orphan next to id=258 (the real input). op_destroy fix → enum snip firings 0, enum C
== oracle byte-exact. So NOT iop-link, NOT cover-semantics — an op_destroy faithfulness bug. Ghidra's
findSubpieceShadow confirmed to also NOT handle INDIRECT (mosura faithful there).

**B-ii RE-MEASURED on op_destroy base — 2 remaining issues (both instrumented, B-ii reverted, clean at
91ddcf7):**
1. **partialmerge snip DIDN'T fire** (ZZ_PM): its LIVE input read `r0x100670:4(i)` (id=109) has
   addrtied=FALSE — it's created by SubVariableFlow narrowing the 8-byte load DURING the pool, AFTER the
   once-only mark_addrtied ran. Ghidra sets addrtied at CREATION (setVarnodeProperties); mosura marks once
   → misses pool-created varnodes. FIX (tested, works): a SECOND `.then(ActionMarkAddrTied)` right before
   ActionMergeRequired → partialmerge snip FIRES `vn=(sp1,0x100670,4)input=true vs vn2=(sp1,0x100670,8)
   def=Copy overlaptype=1 readop=IntAdd`, C stays flat (inlined, correct pre-B-iii). Wire live for B-iii.
   This re-mark added NO new regressions (full-62 diff = only multiret). [Alternative: addrtied-at-creation
   = wider/more faithful; re-mark = staged.]
2. **multiret STILL over-fires** (the SOLE remaining full-62 diff; multiret is UNSCORED so corpus avg
   0.8936 unaffected; oracle-UNCAPTURABLE — "Bytes at 0x100282 not mapped", it's a flow-override fixture
   `override flow r0x10007d callreturn`). multiret has an ALIASED multi-width stack slot: `&xStack_14`
   escapes to func_0x101008, slot -0x14 written at 1-byte(=0x61)+2-byte(=0x3e9). Snip over-fires on the
   INDIRECT-guarded + MULTIEQUAL-merged versions (ZZ_SNIP: all overlaptype=1 PARTIAL, sizes 1/2/4 at -0x14,
   readop=Indirect@… and Multiequal@0x100030, vn2 def=Indirect). partial_copy_shadow returns false because
   the versions are INDIRECT-defined (Ghidra's findSubpieceShadow also doesn't handle INDIRECT → faithful).
   The INDIRECT reads' cover position depends on the guarded-op (iop=INDIRECT input(1)) link mosura OMITS
   (1-input INDIRECT debt) → getUIndex(INDIRECT) in Ghidra = the guarded CALL's order (cover.cc getUIndex),
   mosura uses the INDIRECT's own position. **This is the iop-link contingency the lead gated → report
   scope.** Result = spurious `xStack_14 = xStack_14` self-assigns (7 fixture over-fire → down to just
   multiret after op_destroy). REPORTED to lead for scope decision on the iop-link port.
Instruments used (all reverted): ZZ_SNIP (eliminate_intersect tuples), ZZ_VN/ZZ_PM (varnode dumps).

## TRACK B — B-ii INVESTIGATED + REVERTED (2026-07-09, sb3) — turnkey premise OVERTURNED
B-ii = re-gate mergesnip candidate selection is_memory_space→is_addrtied() (mergesnip.rs:352) + WIRE
`ActionMergeRequired` after condnegate deadcode. Built it (gate change + wiring + updated the 2 mergesnip
unit tests to call mark_addrtied first — needed since the gate is now the real flag). **NET-NEGATIVE
MOVER: corpus 0.8936→0.8896 (-0.004), 6 fixtures regressed** (enum, loopcomment, multiret, partialsplit,
piecestruct, switchhide) — all spurious stack self-assignments `xStack_0 = xStack_0; uStack_10 =
uStack_10;`. partialmerge stayed FLAT (snapshot inlined, expected — needs B-iii). REVERTED to clean B-i
`61147e1` (git checkout the 3 files; tree clean, 350/0).
**ROOT CAUSE (instrument-first, oracle-grounded — turnkey's B-ii premise is WRONG):** the turnkey said
B-i's real addrtied flag would EXCLUDE enum's stack SSA temps ("non-aliased ⇒ not addrtied"). FALSE.
Oracle enum C (capture --c) is clean but passes `axStack_18` (stack buffer at -0x18) to func_0x101000 —
so that stack region's address ESCAPES ⇒ it IS aliased/addrtied in Ghidra too. mosura's mark_addrtied
correctly marks it: enum alias_boundary=-24, so stack offsets 0 and -0x10 (both ≥ -24) get ADDRTIED
(instrument ZZ_MARK: `space=4 off=0x0 +0x208000`, `off=-0x10 +0x208000`). So B-i is NOT over-marking;
it matches Ghidra. The gap is in the SNIP: oracle enum IR has the post-call read of s[-0x10] using the
INDIRECT-created version `s[-0x10]:1(0x00100007:54) = s[-0x10]:1(i) []` (guarded), so Ghidra's
eliminateIntersect finds NO cross-def intersection. mosura's snip DOES fire ⇒ **mosura's
eliminate_intersect OVER-DETECTS an intersection on the INDIRECT-created version that Ghidra doesn't.**
mergesnip.rs's OWN comments already flag this: def_point (line ~199) "INDIRECT approximated by write
position — mosura's 1-input INDIRECT lacks Ghidra's guarded-op link"; boundtype==3 tail case (line ~287)
skipped for the same reason. The enum case is likely boundtype==2/interior on the INDIRECT output version.
**FAITHFUL FIX (needs grounding, NOT started):** ground Ghidra merge.cc eliminateIntersect's handling of
an INDIRECT-def same-address version (is it a shadow it skips? does its 2-input guarded INDIRECT / the
guarded-op link make containVarnodeDef return not-contained?) → port that guard so the snip skips the
INDIRECT-continuation case. Candidate: skip when vn2's def is INDIRECT (ground first — Ghidra's real
reason, likely the guarded-op cover semantics, merge.cc:543-561 + Cover/INDIRECT). partialmerge's
crossing def is a STORE/COPY (not INDIRECT) so a correct INDIRECT-skip won't break it. Re-measure after.
Files touched during B-ii (ALL REVERTED): mergesnip.rs (gate+doc+tests), pipeline.rs (wire). Tree clean
at 61147e1. Reported to lead, WAITING.

B-i NEXT (superseded by above): re-gate mergesnip on is_addrtied + wire — done, regressed, reverted.
Then B-iii = faithful ActionMarkExplicit → partialmerge.

## TRACK B — HELD LANDED + B-i grounded turnkey (2026-07-09, sb2) — GREEN BOUNDARY / handoff
BASE now `345d362` (my coverage.md doc) on `ad7f4b3` (LEAD committed my HELD snip module while I was
reaped — byte-identical to my tree, corpus 0.8936, suite 348/0; NOT a foreign conflict, the expected
reap dynamic). Tree clean. Lead GO'd the staged plan B-i→B-ii→B-iii, each gated; B-iii MUST be the
FAITHFUL ActionMarkExplicit port (its term-count/depth heuristics, coreaction.cc:5719 right after
mergeRequired), NOT a printc "don't-inline-addrtied-COPY" adaptation (dies at gate). mosura's current
explicitness = a single descend-count heuristic at printc.rs:217 (the faithful action subsumes/coexists
— ground which). This chain = P5's first real brick.

**B-i TURNKEY (real early ADDRTIED) — grounded, gated mover, NOT started:**
- mosura sets ADDRTIED on NO varnode today: `Scope::query_properties` (scope.rs:110, the faithful
  queryProperties port that returns MAPPED|ADDRTIED[+PERSIST global] for memory locs) is DEAD — called
  only from its own unit test (scope.rs:174/178); recover_scope (varmap.rs:588) returns symbols, never
  sets vn flags. So `is_addrtied()` is ALWAYS false in the pipeline today.
- Dormant guards that ACTIVATE when the flag is set (⇒ this is a GATED MOVER, not byte-identical):
  rules.rs:6855 (addrtied SUBPIECE → don't convert, leave for CopyMarker), condconst.rs:492/506
  (decline pushing const into an addrtied phi), subvarflow.rs:363 (SubVariableFlow addrtied guard).
  Measure per-fixture, report causes before landing.
- DETERMINATION (faithful queryProperties + the nolocalalias clear): ram (global) → ADDRTIED|PERSIST
  (unmapped ram is addrtied); stack → ADDRTIED **iff** its offset ∈ `alias::aliased_stack_offsets(f)`
  (alias.rs:27 — the address-escapes discriminator = Ghidra's nolocalalias/restructureVarnode clear),
  else NOT addrtied; register/unique/const → not addrtied. NOTE: corpus decompile has NO symbol scope
  (raw_funcdata_flow_image skips the fixture `map addr` script), so use the "unmapped memory" branch by
  SPACE, refined by alias for stack — do NOT rely on a Scope being populated.
- WHY the alias-clear matters: it is EXACTLY what fixes B-ii's over-fire — enum's stack SSA inputs are
  non-aliased ⇒ NOT addrtied ⇒ the snip (gated on the real flag) won't touch them. Global ram (partial
  merge) stays addrtied ⇒ snip enabled.
- PLACEMENT: after heritage/alias info is available, BEFORE the first default_rule_pool (so the dormant
  guards see the flag for the whole pool run — mirrors Ghidra addrtied-before-mainloop). A new
  ActionVarnodeProps-style pass, or fold into the existing heritage tail. Ground the exact insertion
  point in pipeline.rs (heritage runs early; rule pools follow).
- Then B-ii: re-gate mergesnip candidate selection on `is_addrtied()` (replace the is_memory_space
  proxy at mergesnip.rs merge_required) + WIRE the snip → over-fire should vanish, partialmerge still
  flat (snapshot inlined) until B-iii. B-iii: faithful ActionMarkExplicit → partialmerge lands.

## TRACK B — (A) Merge-snip BUILT + wired-test = REGRESSES; needs 2 prerequisites (2026-07-09, sb2)
Built the faithful snip: `mergesnip.rs` (ActionMergeRequired → merge_required/mergeAddrTied +
eliminate_intersect + snip_reads + characterize_overlap + partial_copy_shadow/find_subpiece_shadow/
find_piece_shadow + contain_varnode_def) + cover.rs `cover_to_read`/`block_range`. 2 unit tests PASS
(partialmerge shape snips into a unique COPY; non-crossing read isn't snipped). HELD/unwired = suite
348/0, corpus 0.8936 byte-identical. Module KEPT unwired (faithful, tested, ready) — NOT reverted.

**Wired-test (instrumented, then UNWIRED): NET-NEGATIVE mover 0.8936→0.8885.** The IR-level snip is
correct but wiring regresses because mosura lacks 2 pieces of Ghidra's surrounding merge-phase machinery:
1. **printc inlines the snapshot.** On partialmerge the snip DID fire (`SNIP sp1:0x100670:4 input=true`)
   inserting `u=COPY r0x100670:4(i)`, but printc treats the single-use unique COPY as IMPLICIT and
   inlines it back into the ADD → prints `return iRam...+10` again (global re-read). Snapshot DEFEATED,
   partialmerge unchanged 0.786. Ghidra keeps it EXPLICIT (ActionMarkExplicit @coreaction.cc:5719, right
   after mergeRequired) so it prints as the named temp `a_simple`.
2. **space-proxy over-fires.** Candidate gate = ram/stack space (the addrtied proxy) over-includes stack
   SSA INPUT varnodes. On enum the snip fired on `sp4:0x0:8 input=true` + `sp4:-0x10:1 input=true` (stack
   inputs) → spurious `xStack_0 = xStack_0; uStack_10 = uStack_10;` self-assignments → enum 1.000→0.826,
   threedim 1.000→0.978, partialsplit/piecestruct/stackreturn/switchhide down. Ghidra does NOT snip these
   (its real ADDRTIED flag excludes non-address-taken stack SSA temps; oracle enum has no such temp).
So BOTH lead-flagged "design points" are PREREQUISITES, not follow-ups: (a) a REAL addrtied flag computed
BEFORE the snip (gate on it, not the space-proxy) to stop the over-fire; (b) explicit-marking of the
snapshot (port ActionMarkExplicit, or make printc not inline a COPY of an addrtied varnode whose address
is later written) so the snapshot survives as a named temp. The snip is necessary-but-not-sufficient; it's
a merge-PHASE port (mergeRequired + markExplicit + addrtied timing), the "read-only merge vs mutating
merge" architectural class. Reported to lead; awaiting direction (build the 2 prereqs, or scope down).
Files: mergesnip.rs (HELD), cover.rs (+cover_to_read/block_range), mod.rs (+mergesnip), pipeline.rs
(snip line commented-out with the why). Base still `02a7840`, tree has the HELD module uncommitted.

## TRACK B — stackstring MECHANISM CORRECTED + (A) Merge-snip grounding (2026-07-09, sb2, read-only)
**stackstring split rule = `lanedivide` (NOT RuleSplitCopy/SplitDatatype).** Trace DEBUG 64 `lanedivide`
= `ActionLaneDivide` (coreaction.cc:585, .hh:113, in the `stackstall` group @coreaction.cc:5652). It
lane-divides the 16-byte laned XMM: `XMM0 = r0x100250:10(free)` → `XMM0_Qa = r0x100250` + `XMM0_Qb =
r0x100258` (via LaneDivide/SplitFlow), so each stack store is 8-byte. THEN `storevarnode`=RuleStoreVarnode
(DEBUG 68-71) converts each `*(ram,RSP+off)=val` STORE → stack-slot COPY `s0xffffffff...` — the spacebase
rule mosura's stackvars already does pre-pool. So task #6 mislabeled: the driver is ActionLaneDivide
(laned-vector split), not the SplitDatatype composite-struct cleanup (RuleSplitCopy/Store @5706-5708,
which did NOT fire here). RuleSplitStore may still matter for non-vector composite stores elsewhere, but
stackstring specifically needs ActionLaneDivide. Told lead to re-title #6.

**(A) Merge addrtied-snip — grounding (per lead's 2 design points):**
Full chain: ActionMergeRequired (coreaction.cc:5718, group "merge" — runs AFTER cleanup pool + structure
xform, BEFORE ActionNameVars/SetCasts/print @5734-5735) → Merge::mergeAddrTied (merge.cc:609: space
filter `type==IPTR_PROCESSOR||IPTR_SPACEBASE` @617, snip gated `flags&addrtied` @631) → unifyAddress
(:581) → eliminateIntersect (:489, per-read Cover vs same-addr blocksort, containVarnodeDef+
characterizeOverlap+partialCopyShadow) → snipReads (:443, allocateCopyTrim COPY at vn's def point; input
→ opInsertBegin(block0)).
- **Design pt 1 (addrtied timing):** Ghidra sets addrtied EARLY (all before mergeRequired @5718): stack
  locals via ActionRestructureVarnode (mainloop "localrecovery" @5505 → syncVarnodesWithSymbols
  funcdata_varnode.cc:938 → `mapped|addrtied` @976); globals via Scope::queryProperties from the
  (pre-mapped) global symbol at ActionVarnodeProps/heritage time (partialmerge `map addr r0x100670`
  makes the symbol exist from t0). mosura HAS the identical calc — `scope.rs:110 query_properties` (=
  Scope::queryProperties, memory-space unmapped → `MAPPED|ADDRTIED`, +PERSIST global) — but runs it ONLY
  at print time (recover_scope, printc.rs:528). So mosura's late ADDRTIED IS a real timing divergence.
  Faithful-enough path for the snip: key it on mergeAddrTied's SPACE filter (ram/stack) + query_properties
  — within processor/spacebase, unmapped memory ⇒ addrtied, so the space filter ≡ the addrtied gate here;
  don't invent a workaround. Moving the addrtied calc earlier = a documented follow-up (its own divergence).
- **Design pt 2 (read-only merge vs mutating):** mosura `merge::merge(&Funcdata)->HighVariables` is
  IMMUTABLE — read-only naming, called printc.rs:19 + infertypes.rs:35 — same class as the read-only
  structurer (isBooleanFlip S1). Placement already aligns (Ghidra merge phase ≈ mosura's late printc-time
  merge). Port = a NEW mutating pass (ActionMergeRequired-equiv: mergeAddrTied→eliminateIntersect→
  snipReads) BEFORE the read-only merge/printc, insert snip COPYs + re-run deadcode; document as once-pass
  approx; tie to mainloop-repeat backlog rock. mosura ALREADY has the infra: Cover (cover.rs) computes the
  intersection, classes_interfere (merge.rs:103) DETECTS it, new_op+op_set_input+total_replace do the
  insert/repoint. New code = eliminateIntersect's per-read cover-vs-same-addr-def scan + snipReads' COPY-
  at-def-point. Reported to lead; WAIT for gate.

## TRACK B — stackstring instrument (2026-07-09, sb2, read-only, probe deleted) — ALSO not spacebase
stackstring scored fn = chunk[0] @0x100000: a stack-string builder — stores bytes/dwords + a 16-byte
`movaps [rsp],xmm0` (xmm0 = `[ram 0x100250]` const string) into `[rsp+N]` slots, then passes rsp/
rsp+0xc to two calls (buffer addr ESCAPES). mosura's stackvars ALREADY reduces the stores to spacebase
slots (`s0xffffffff...`), and guardCalls ALREADY inserts the INDIRECT guards across both calls (present
in final IR). So guardStores/guard-INDIRECT is NOT the gap.
DIVERGENCE = **wide-store SPLITTING.** Ghidra splits the 16-byte movaps store into two 8-byte stack
slots reading two 8-byte ram halves: `s[-0x28]=r0x100250(i)` + `s[-0x20]=r0x100258(i)` (oracle IR
0x10001d:53/54) → prints `xStack_28 = xRam...100250; xStack_20 = xRam...100258;`. mosura keeps ONE
un-split `s0xffffffffffffffd8:16 = INDIRECT r0x100250:16` → printer drops it (declares `&xStack_28`
in the call but never assigns it). mosura has NO split subsystem: no RuleSplitCopy/RuleSplitStore/
RuleSplitLoad/SplitDatatype (grep-confirmed). Ghidra: cleanup pool RuleSplitCopy("splitcopy") +
RuleSplitLoad/RuleSplitStore("splitpointer") (coreaction.cc:5706-5708), driven by SplitDatatype
(splitdatatype.cc), split a composite (struct/array/vector) COPY/LOAD/STORE into per-field pieces.
So stackstring = port RuleSplitCopy/RuleSplitStore (+SplitDatatype), ORTHOGONAL to both the spacebase
model AND the partialmerge Merge-snip.

NET (both track-B validation targets re-attributed, spacebase premise fully overturned):
- partialmerge 0.786 → Merge::mergeAddrTied/eliminateIntersect/snipReads (+ActionMergeRequired).
- stackstring 0.794 → RuleSplitCopy/RuleSplitStore (SplitDatatype cleanup).
- The RuleLoadVarnode/RuleStoreVarnode/spacebase-placeholder model is a real Ghidra subsystem but
  NEITHER headline fixture needs it. Reported both to lead; awaiting re-scope.

## TRACK B — SPACEBASE MODEL: staging proposal (2026-07-09, sent lead, WAIT for go)
Validation targets: partialmerge (0.786, CORRECTNESS bug = highest priority) + stackstring (0.794);
impliedfield (0.921) = guard-against-regression. partialmerge proven root: mosura collapses the
const-addr LOAD into a direct ram-varnode read at the USE site (after the store) — `r0x100670:4 + 0xa`
reads the stored value; oracle keeps the load at 0x1006a7 reading the pre-store INPUT version
(`u0x10000008:4 = r0x00100670:4(i)`). = lost sequence point; the faithful fix is RuleLoadVarnode
(COPY at the load's op) + heritage guardLoads versioning.

STAGES (JumpBasic-style; each gated where it moves):
- B0 READ-ONLY: pin mosura's CURRENT const-addr LOAD/STORE→ram-varnode collapse (NOT stackvars, NOT a
  named rule yet — likely heritage ram-collection or build). Name the exact code + why the load loses
  its sequence point. (stackvars = the KNOWN stack-relative overlap; guard_stores heritage.rs:772 partial.)
- B1 helpers byte-identical/unwired + unit-tested: correctSpacebase/vnSpacebase/checkSpacebase
  (ruleaction.cc:4173-4263) — recognize `const` or `spacebase_input+const`. Needs stack reg registered
  as the stack-space spacebase (ActionSpacebase / spec); check if SpaceManager already knows RSP-spacebase.
- B2 RuleLoadVarnode/RuleStoreVarnode HELD unwired + unit-tested (ruleaction.cc:4277/4319): LOAD→COPY(space
  vn), STORE→ vn=COPY(val)+setStackStore. DEFER the isSpacebasePlaceholder trigger to B5.
- B3 heritage guardLoads (heritage.cc:1570) + LoadGuard list + discoverIndexedStackPointers (:986): make
  the LOAD read the correct pre-store SSA version. THE correctness stage for partialmerge. DANGER ZONE.
- B4 WIRE gated + CANCEL the overlapping pre-pool conversions (stackvars STORE/LOAD→stack-COPY + the B0
  const-addr collapse), per no-adaptation-grandfathered. KEEP the orthogonal SP-tracking (either retain a
  reduced stackvars for RSP→spacebase+const normalization OR port ActionSpacebase/StackPtrFlow to replace
  it). Gate: partialmerge (correctness) + stackstring + impliedfield-no-regress + full corpus.
- B5 spacebase_placeholder + resolveSpacebaseRelative (fspec.cc:4856/4870/5174, coreaction.cc:1503): SP-
  across-call recovery. Follow-on, only if a fixture needs it. Separate gate.

RISK MAP (heritage = danger zone): (1) B3 load-before-store VERSIONING — wrong version silently corrupts
values (partialmerge-class); highest risk; mitigate w/ oracle-IR-at-heritage instrument + versioning unit
test. (2) B4 canceling stackvars too aggressively — if stack addrs stop reducing to spacebase+const the
rules won't fire → mass regression; stage the cancel, keep SP-tracking until ActionSpacebase replaces it.
(3) pool/heritage convergence — mosura's hand-unrolled pipeline (heritage restart-group THEN pool) differs
from Ghidra's mainloop; STORE→LOAD forward needs a heritage pass AFTER the rules convert; may need an extra
iteration. (4) setStackStore/markNotMapped/addrtied feed recover_scope/varmap → naming/typing shifts.
(5) impliedfield relies (post track-A) on stackvars' stack-forward — canceling must preserve it.

## TRACK A ✅ COMPLETE + LANDED — master `02a7840` (2026-07-09)
Cross-block cseElimination in RuleSelectCse (full both-arm faithful port). Lead-gated, committed.
Post-land re-verify on master: suite 346/0, corpus avg 0.8905→**0.8936**, **impliedfield 0.733→0.921
SOLE mover**, zero regressions. Headline below-baseline gap closed. Residual 0.921 = casts +
`val.u.myfloat` union naming = downstream P4-types/P6, separate. Detail in the "TRACK A BUILT" section
below + the commit message. NEXT: track (B) spacebase model — staging proposal (gated, report+WAIT).

## TRACK A BUILT (2026-07-09) — [landed as 02a7840, above]
Lead said GO on (A) with the requirement: port cseElimination COMPLETELY (both dominance arms), not
just the probe. DONE (uncommitted on base `28d07c2`, tree = rules.rs + condconst.rs + docs/coverage.md):
- rules.rs: `cse_hash` (op.cc:130), `is_cse_match` (op.cc:153), `cse_elimination` (funcdata_op.cc:1356,
  BOTH arms: one-dominates→keep dominating op; neither-dominates→`build_cse_at_common` at findCommonBlock),
  `cse_eliminate_list` (funcdata_op.cc:1418, hash-sort + adjacent-pair + full is_cse_match). RuleSelectCse
  rewritten to collect in(0) descendants + call cse_eliminate_list (ruleaction.cc:187).
- condconst.rs: `find_common_block` made `pub(crate)` (reused per lead, block.cc:736).
- Omitted-guard notes IN CODE: eval-type (op.cc:134/156) subsumed by SUBPIECE/SRIGHT opcode filter;
  isHeritaged (funcdata_op.cc:1436) always-true post-heritage + absent in prior same-block code.
- 2 unit tests: neither-dominates hoist-to-common-dominator + one-dominates keep. Suite 346/0 (344+2).
MEASURED (full port == probe, neither-dominates arm doesn't fire on corpus): **impliedfield 0.733→0.921
SOLE mover**, corpus avg 0.8905→0.8936, 45/45 other fixtures unchanged, none crossed 1.000. Residual
0.921 = casts + `val.u.myfloat` union naming (P4-type/proto), separate.
STATUS: reported delta table to lead; WAITING for landing go (mover gate). On go: commit (Co-Authored-By
trailer), flip nothing else. Then track (B) spacebase becomes the next rock.

RECOMMENDATION sent to lead (SUPERSEDED — lead chose A-then-B): RE-SCOPE task #1. The impliedfield fix = faithful port of the cross-block
branch of `cseElimination` into RuleSelectCse (a MOVER, gated). The spacebase model (RuleLoadVarnode/
RuleStoreVarnode + guardStores/guardLoads + ActionSpacebase/StackPtrFlow) is still a real faithful-port
target but for OTHER fixtures: partialmerge (correctness bug — reads NEW global value instead of
snapshotting OLD; constant-addr load/store ordering) + stackstring (drops stores to stack slots whose
address ESCAPES to a call — guardStores INDIRECT). Awaiting lead decision before any code.

## Ghidra spacebase model — grounded inventory (for when the spacebase track is greenlit)
- RuleLoadVarnode/RuleStoreVarnode (ruleaction.cc:4173-4341): LOAD/STORE off spacebase+const → COPY
  of/into a space varnode. checkSpacebase(:4236)→vnSpacebase(:4194)→correctSpacebase(:4173) recognize
  `const` OR `spacebase_input + const` (or via SEGMENTOP). STORE sets setStackStore + markNotMapped if
  StoreUnmapped. Placeholder trigger (LOAD only): if out isSpacebasePlaceholder → resolveSpacebaseRelative.
- spacebase_placeholder (varnode.hh:129,261,319) = artificial varnode tracking stackpointer across a
  CALL. Created: fspec.cc:4856 + 5174 (FuncCallSpecs), coreaction.cc:1503 (ActionLoadVarnode-ish).
  resolveSpacebaseRelative (fspec.cc:4870). This is the SP-across-call subsystem (separate concern from
  the STORE→LOAD forwarding; not needed for the three fixtures above).
- heritage.cc guardStores(:1538)/guardLoads(:1570): add INDIRECT (store) / COPY-guard (load) so aliased
  indexed-stack accesses prepopulate data-flow; gated on highPtrPossible + addrtied. discoverIndexedStack
  Pointers(:986). This is the stackstring escape mechanism.
- mosura stackvars OVERLAP-vs-ORTHOGONAL: the STORE/LOAD→stack-COPY conversion OVERLAPS RuleStore/Load
  Varnode (cancel per no-adaptation-grandfathered). The symbolic SP tracking (`symbolic_value`) ≈ Ghidra
  general simplification reducing addr to `RSP_input+const` + ActionSpacebase (register stackreg as
  spacebase); `call_push_restores` ≈ ActionStackPtrFlow SP-solver/extrapop. Those are the KEEP/port-
  separately pieces.
