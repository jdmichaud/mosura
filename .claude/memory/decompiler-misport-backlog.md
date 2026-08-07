---
name: decompiler-misport-backlog
description: "D2–D6: five verified decompiler MIS-PORTS (Ghidra correct, mosura diverges) found by the analysis track's source-owned ground-truth oracle; handoff docs + repro binaries in master @19f1f6b. FOR THE DECOMPILER AGENT."
metadata: 
  node_type: memory
  type: project
  originSessionId: df001909-493d-4f50-92ac-53ef8ca6337d
  modified: 2026-07-22T06:51:10.452Z
---

**FOR THE DECOMPILER/MAIN AGENT — user-directed handoff (2026-07-21).** The analysis
track's ground-truth bug-hunt (source-owned corpus, `oracle/ground-truth/`, gate
`tests/ground_truth_parity.rs`) found five decompiler mis-ports. Each was CLASSIFIED
against Ghidra's own decompiled C (analyzeHeadless + DecompInterface on the same stripped
binary): in every case **Ghidra is correct and mosura diverges** — real port bugs, not
beat-Ghidra extensions. All repro material is in master @`19f1f6b`.

**Priority order (per blast radius):**
1. **D5 — RETURN-CAPTURE half ✅ LANDED `4e633e7` (2026-07-22; lead verified all 3 Ghidra citations + re-ran gates 0.9540/57, 528/0, clippy 0).**
   The `extraout_RAX` / dropped-return WAS the real faithfulness mis-port: mosura's `guard_calls`
   spliced call INDIRECTs AFTER the call + `resolve_call_output` scanned forward, a mutually-consistent
   ADAPTATION that Ghidra doesn't share (Ghidra `newIndirectCreation`/`newIndirectOp` = `opInsertBefore`,
   funcdata_op.cc:696/726; `collectOutputTrialVarnodes` walks BACKWARD, fspec.cc:5543). The faithful
   `RulePullsubIndirect` (`opInsertBefore`) moved the return INDIRECT before the call, where the forward
   scan couldn't see it. **Fix = 3 matched faithful changes:** (a) guard_calls → `op_insert_before`
   (heritage.rs:1508/1517); (b) resolve_call_output → backward scan (recover.rs:913); (c) the MISSING
   faithful piece — `current_def_at_op` porting Ghidra's "INDIRECTs and their op happen AT SAME TIME"
   rename rule (heritage.cc:2506-2517), so a reg that is both arg+killedbycall (RDI/…) feeds the call
   its ARG not the clobber. **Corpus 0.9528→0.9540 (+0.0012); ONLY movers switchmulti +0.031 (now
   byte-EXACT on arg region vs oracle) + stackreturn +0.037 (ordering now oracle-faithful); multiret
   byte-changed but UNSCORED (empty oracle) — pre-existing passthrough-INDIRECT-as-assignment artifact
   relocated, no new wrong-code. Zero regressions.** Verified: deepchain full chain + recursion `fib`
   self-call all capture the return (`iVar3 = func_0x00401070(uVar2-1); iVar1 += iVar3;`). suite 528/0,
   gt-parity pass, jumptable 6/6, ir_parity 9/9, clippy 0.
   **NAMING half = NOT a mis-port (reclassified):** `func_0x<addr>` vs `FUN_<addr>` AND `xunknown<N>`
   vs `undefined<N>` are DATATEST-CAPTURE-oracle vs analyzeHeadless CONTEXT artifacts — the datatest/
   isolated-decompile oracle ITSELF emits `func_0x`+`xunknown` (verified via `oracle/capture --c`), which
   mosura matches. `FUN_`/`undefined` only appear in full analyzeHeadless (symbol/type DB present).
   Fixing D5's naming = threading a function-symbol resolver into printc for the FULL-ANALYSIS path
   (decompile_function has the function_manager; printc has no Program ref) — a bounded SEPARATE feature,
   NOT a decompiler mis-port. Doc: `docs/decompiler-bug-d5-known-call-func0x-extraout.md`.
2. **D4 — PRIMARY mis-port ✅ FIXED (2026-07-22, build agent; pending lead land, tree dirty @4e633e7).**
   The empty-infinite-loop silent wrong-code: mosura's decompiler flow (`raw_funcdata_flow_image`)
   re-decoded from the image and FOLLOWED the tail-`jmp` into the other function's body (is_even@401000
   →is_odd@401020→back to 401000 = bogus back-edge-to-entry loop), never consulting the analysis's
   flow overrides. mosura's analysis ALREADY detects the tail call (`SharedReturnAnalyzer`,
   analyzers/shared_return.rs) and models it by retyping the jmp's flow reference to `UnconditionalCall`
   — but that never reached the decompiler. **Fix = wire the analysis override into the flow builder:**
   `decompile_function` collects call-typed reference sources (`ref_type.is_call()`) and passes them to
   new `raw_funcdata_flow_image_overrides`; when decoding an instruction at such an address whose last
   op is a BRANCH (a real `jmp`, so normal `call`s are untouched), rewrite BRANCH→CALL + trailing RETURN
   (Ghidra `FlowOverride::CALL_RETURN` / `overrideFlow`, funcdata_op.cc:997-1009; flow.cc:416/475),
   applied BEFORE the succ/fallthru scan so the callee body isn't followed. Mirrors the existing
   BRANCHIND→CALLIND `truncateIndirectJump` precedent (build.rs). **CORPUS BYTE-NEUTRAL** (0.9540/57 —
   datatest path passes empty overrides; only the multi-function analysis bridge supplies them). The
   empty loop is GONE: is_even = `if(param_1==0) return 1; func_0x00401020(param_1-1); return;`, is_odd =
   `func_0x00401000(param_1-1); return;` (byte-IDENTICAL to Ghidra except func_0x naming). suite 528/0,
   gt-parity pass, jumptable 6/6, clippy 0.
   **RESIDUAL — is_even drops the tail-call's RETURN VALUE (Ghidra `uVar1 = FUN_..(); return uVar1`) = DEEP,
   NOT bounded, NOT specific to D4.** Root cause pinned: a direct `return h()` where the call result's
   ONLY use is the RETURN. resolve_return (ReturnRecovery) prunes the RAX candidate via `is_realistic`
   (recover.rs:74) rejecting the killedbycall INDIRECT-creation, BEFORE resolve_call_output (ActiveReturn,
   fullloop tail) can promote it → RAX dies → never captured. Ghidra's `AncestorRealistic::enterNode`
   (funcdata_varnode.cc:2046-2050) returns `pop_success` (valid!) for an indirect-creation whose input is
   NOT `isIndirectZero` — i.e. `possibleout=true`, a killedbycall reg registered as a call OUTPUT trial
   (`isOutputActive`/`characterizeAsOutput`, guardCalls heritage.cc:1468-1522). **mosura's guardCalls
   NEVER sets `possibleout` (the documented P6 output-trial gap) → all creations are isIndirectZero → is_realistic rejects
   them.** Fixing = the guardCalls possibleoutput/isOutputActive output-trial machinery (P6) — multi-pass
   (ActiveReturn setup → re-heritage guardCalls → AncestorRealistic). NOTE: DISTINCT from D3 (now fixed):
   D3 is the `AncestorRealistic` unwritten-INPUT base case (return-of-input-derived-value); the D4
   residual is the indirect-creation `possibleout` case (return-of-CALL-result). Both live in the same
   AncestorRealistic port but are different arms (base-case vs INDIRECT-case). Recompile note: is_even's
   `return;` is ABI-accidentally-correct (RAX
   still holds the callee result) but not clean C. Doc: `docs/decompiler-bug-d4-tailcall-empty-loop.md`.
3. **D3 ✅ FIXED (2026-07-22, build agent; pending lead land, tree dirty @64524b7).** The two
   observations reconcile to ONE mechanism (NOT structure/switch-specific, NOT constant-0x100-specific):
   the return VALUE is derived from an INPUT parameter and the ancestor traversal reaches an UNWRITTEN
   INPUT, which mosura's `is_realistic` (recover.rs:45) rejected. dispatch case5 `y|0x100` = `mov eax,esi;
   or ah,1` (a SUB-REGISTER write → EAX reconstructed as a PIECE whose low piece is the input esi);
   fallthrough case2 `return param_2` = `mov eax,esi` (EAX = COPY/IntZext of input esi). Both trace to
   the unwritten input `param_2`. **Root cause = mis-port of `AncestorRealistic`:** Ghidra's `execute`
   (funcdata_varnode.cc:2205) early-returns false ONLY when the trial varnode is DIRECTLY an input; a
   value reached THROUGH a copy/piece chain to an input traverses via `enterNode` → `pop_success` (a
   normal parameter, :2040). mosura conflated the two — returned false for ANY unwritten value.
   **Fix (recover.rs, faithful):** (a) `is_realistic` unwritten base case `false`→`!is_return_address()`
   (enterNode pop_success); (b) `return_trial_kept` adds the top-level `is_input()`→false guard (execute
   :2205). dispatch + fallthrough now byte-MATCH Ghidra (`return param_2 | 0x100;` / `return param_2;`).
   **Corpus 0.9540→0.9513; ONE byte-mover: partialunion −0.158 = NET CORRECTNESS improvement** (baseline
   was spuriously `void func`, oracle + fixed both non-void returning the global; the −0.158 fuzzy score
   is a SEPARATE downstream rendering gap — RAX-not-merged-with-global HighVariable → intermediate
   `xVar1 = xRam..; return xVar1;` vs oracle `return xRam..;` = the C-cluster HighVariable-merge
   foundation, out of scope). Zero wrong-code; void functions stay void (top-level guard); D4-residual +
   D5 unaffected. suite 528/0, clippy 0, jumptable 6/6, gt-parity pass. Also note the `xunknown4` vs
   `undefined4` naming is the SAME context artifact as D5 (datatest oracle uses xunknown; not a mis-port).
   Doc: `docs/decompiler-bug-d3-switch-or-value-drop.md`.
4. **D6 — GROUNDED, verdict DEEP (2026-07-22, build agent; NOT built, HOLD).** int64 signed `/`/`%`
   over-widened to 128-bit `(int16)`. Mechanism fully traced (created a datatest XML for the divmod64
   bytes at 0x401010 → `oracle/capture --ir/--c` + `oracle/capture_trace --trace`). **Ghidra narrows the
   128-bit `cqo;idiv` to 64-bit via a 3-rule chain:** (1) `signform` (RuleSignForm): `SUB168(SEXT816(RDI),8)`
   [the cqo sign-smear high half] → `RDI s>> 0x3f`; (2) `piece2sext` (RulePiece2Sext): `CONCAT88(RDI s>>0x3f,
   RDI)` → `SEXT816(RDI)`; (3) `subcommute` (RuleSubCommute, INT_SDIV/SREM arm): `SUB168(SDIV(SEXT816(RDI),
   SEXT816(RSI)),0)` → `SDIV(RDI,RSI)` 64-bit. **mosura HAS all 3 rules, wired (pipeline.rs:211/240/241,
   rules.rs:4487/6607/8514) — they narrow the 4-BYTE case (cdq, `(int4)x/10`, switchloop) per code comments
   — but NONE fire for the 8-byte case.** mosura trace: only earlyremoval/shiftpiece/propagatecopy/piece2zext
   fire; signform/piece2sext/subcommute never do. Root: the cqo sign-smear `SUBPIECE(SEXT816(RDI),8)` (raw
   p-code confirms `r0x10 = SUBPIECE(u0x7af00:16,#8)`, correct) COLLAPSES to constant `#0x0` during heritage/
   simplification BEFORE signform runs → `shiftpiece`+`piece2zext` make the dividend `ZEXT(RDI)` → the
   128-bit SDIV stays. **This is mosura's documented u64-only-nzmask / 16-byte(128-bit) double-precision
   limitation (nzmask.rs:10 "Ghidra's extended-precision size>sizeof(uintb) branches collapse"; the SUBPIECE
   nzmask nzmask.rs:213 skips the truncation shift for in_size>8, so a 16-byte SEXT's high-byte SUBPIECE is
   mis-analyzed). Ghidra's size>8 extended-precision nzmask (which mosura collapses) keeps the sign-smear
   alive.** DEEP — the 128-bit nzmask/double-precision foundation, multi-mechanism; related to [[task9-subvariableflow-plan]]
   (RuleSubvarSext deferred) + [[task9-stage3-blocker]]. Semantically equivalent for in-range (ABI-correct),
   so lower severity than D3/D4/D5 wrong-code. Doc: `docs/decompiler-bug-d6-int64-div-overwiden-128.md`.
5. **D2** — `resolve_call_output` OOB panic (block[2] on 1-block CFG) on the
   `tm_clones` `jmp *rax` idiom; still reproduces @a8081f7 (panic now funcdata.rs:244).
   Mitigated by the analysis bridge's catch_unwind (keep that net), root cause unfixed.
   Doc: `docs/decompiler-bug-tm-clones-panic.md`.

Each doc is self-contained: repro binary (committed, e.g. `oracle/ground-truth/
dispatch.gcc-x86-64` / `tailcall.gcc-x86-64` / `deepchain.gcc-x86-64` /
`arith64.gcc-x86-64`) + address + SOURCE + mosura C + Ghidra C + verdict. Reproduce with
`cargo run -q --example gt_recompile_probe -- <binary> <hexaddr>`. Findings where mosura
== Ghidra (irreducible CFG, nested loops) were deliberately NOT filed — faithful.

Analysis-track context: [[direction-analysis-port]] (that track is consolidated-clean;
these are its yield). The corpus itself: [[self-compiled-ground-truth]].
