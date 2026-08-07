---
name: adaptations-inventory
description: "Verified read-only audit (audit1 @a2211f3, 2026-07-18) of ALL remaining non-Ghidra adaptations in the mosura DECOMPILER: 19 remaining + 3 minor/candidate, grouped by category, file:line-cited, with the verified-retired list. The big pipeline-core adaptations ARE retired; structural/list/timing ones remain. Highest-value: A1 (faithful cspec loader exists, unwired)."
metadata: 
  node_type: memory
  type: reference
  originSessionId: 9beadf25-4682-4e85-94fa-f326d85ed777
  modified: 2026-07-31T00:56:13.925Z
---

## ✅ TREE-VERIFIED RE-AUDIT 2026-08-03 (after F2 retired `c742592`) — the register was OVERCOUNTING

Each item read at its site on HEAD. The honest count is LOWER than 13, and what remains is NOT a set of one-token fixes.

**RETIRED / ALREADY-DONE / RECLASSIFIED (so NOT open inventions):**
- **F2** bool-propagation width→nzmask — RETIRED `c742592` (Ghidra `getNZMask()>1`, coreaction.cc:5096/5363; corpus 0.9561 unchanged, suite 505/0). This was the LAST "documented approximation with the faithful mechanism already in the tree" = the last cheap-tier item.
- **phi input slot order** — ALREADY RETIRED in the tree (cfg.rs:263 iterates predecessors in op-CREATION order = faithful `FlowBlock::addInEdge`, block.cc:73; comment literally says "Retires the former ascending-block-index in_edge sort"). Register was stale.
- **D2 `mark_addrtied`** — NOT an invented heuristic: it is a FAITHFUL port of Ghidra's `syncVarnodesWithSymbols` reconcile side (funcdata_varnode.cc:1046) with a documented STAND-IN (alias analysis directly, because the decompile corpus has no populated ScopeLocal). Reclassify.
- **minors** `check_call_double_use` position (stand-in for `getSeqNum().getOrder()`, mosura has no global op order) and **LaneDivide lanedMap** (re-derived from live varnodes, behavior-equiv to Ghidra's incremental map) — faithful stand-ins for architectural gaps, not inventions. Reclassify.

**GENUINELY OPEN — and each is a REAL Ghidra-subsystem port, not a one-token change:**
- **C-cluster (architectural):** C1 `structure()` re-derived at 18 sites vs one persistent mutating BlockGraph · C3 no persistent HighVariable (7 rebuild sites) · C2 XOR-not-edge-reversal (gated on C1). These are the persistent-object foundation — weeks, not turns.
- **D-cluster (C-coupled):** D1 merge once at tail · D3 orient/prefer once at tail — move into the repeating structure once C1 exists.
- **B-cluster (print-time → IR, MEDIUM real ports):** B1 `is_explicit` (partly frozen to IR flags already; remaining arms need more of `ActionMarkExplicit`/`baseExplicit` in the IR) · B3 print-time De Morgan (needs `ActionNormalizeBranches`) · B4 print-time switch label/index heuristics (→ `BlockSwitch` methods).
- **F1** RuleEqual2Zero's omitted all-descendants-bool guard — COUPLED: switchloop's jumptable recovery depends on the extra firing (documented in-code); restoring the guard needs the switch-path IR divergence fixed first.
- **G1** the up-front alias CLONE-PROBE — entangled (Stage B flips its `call_guards_active`); Ghidra runs AliasChecker inline from `ScopeLocal::restructureVarnode`, so retiring it is bound up with populating ScopeLocal.

**⇒ HONEST STATE: after F2, the cheap tier is EXHAUSTED. The remainder is one architectural foundation (C-cluster, which unblocks D), three medium print-time ports (B-cluster), and two coupled items (F1, G1). Real ports, done one at a time — not twelve one-liners.**

## ⛔ SCOPE WARNING 2026-07-31 — "ADAPTATION list now EMPTY" DOES NOT MEAN THIS REGISTER IS EMPTY

Commit `147adaf`'s subject says the ADAPTATION list is empty, and that is TRUE **only in
`scripts/trace-names.py`'s sense**: every `impl Rule for X` / `impl Action for X` in mosura now
names a Ghidra class (148/148). That audit reads ONE thing — the Rule/Action **class vocabulary**.
It is blind to every adaptation that lives INSIDE a faithfully-named class or outside the
Action/Rule shape entirely, which is where most of this register lives:

  · **G1** the alias clone-probe — sits *inside* `ActionHeritage::apply`, a faithfully-named action
  · **C-cluster** — an architectural ABSENCE (no persistent BlockGraph/HighVariable); nothing to name
  · **B-cluster** — print-time logic in printc.rs, not a Rule at all
  · **D-cluster · F1/F2 · phi slot ordering · the minors** — wrong stage / wrong order / missing
    guard *within* faithful classes

⇒ Three invented RULES were retired (`RuleMultMult` 5c9afe2, `RuleIdempotent` 9c4bd10,
`RuleRangeAnd` 147adaf). The register below is UNCHANGED by that work. Read the audit's empty list
as "the rule pool no longer carries a rule that names no Ghidra class, and the audit is now the
standing check that it never grows one" — never as "no inventions remain".

**HONEST COUNT, RE-VERIFIED AT THE SITES @`a144a43` (master): 13 REMAIN — none retired by the rule
work.** G1 alias clone-probe (pipeline.rs:62, still labelled PROBE-DIAGNOSTIC) · C1 `structure()`
re-derived — **now 23 call sites, UP from 20**, the only item that MOVED and it moved the wrong way ·
C2 block_negate XOR-not-edge-reversal · C3 no persistent HighVariable (7 `HighVariables::new` sites)
· B1 print-time `is_explicit` (8 sites in printc.rs) · B3 print-time De Morgan (printc.rs:1248) ·
B4 print-time switch_index/case_labels (4 sites) · D1 merge once at tail (pipeline.rs:779) · D2
addrtied by scan · D3 OrientBranches/PreferComplement once at tail (pipeline.rs:764) · F1
RuleEqual2Zero's missing all-descendants-bool guard · F2 bool propagation approximates nzmask with
width · phi input slot order by block-index not `addInEdge` order · plus the two minors.
The three retirements were REAL but they were the cheap tier: standalone invented rules with a
faithful twin already in the tree. Everything left is structural, and C1 GATES C2/D1/D3.

## ⚠️ RE-VERIFIED AGAINST THE TREE 2026-07-30 @8aa73c3 — **13 of the audited 15 remain**

**RETIRED since the 07-29 audit (verified at their sites):** **A3** `RSP=0x20` — landed `9439fcf`; space.rs:260 is now only the FALLBACK for a spec-less hand-built SpaceManager, and `set_stack_pointer` replaces it from `analysis::cspec::default_stack_pointer` (Ghidra reads `<stackpointer>`; so does mosura whenever a spec exists) ⇒ FAITHFUL, not an invention · **B2** stack-symbol naming/typing — landed `66570a4` (COMPILE_FAIL 95→61, undeclared locals 32→0) · **`type_prefix`** — landed `8aa73c3` (`Datatype::printNameBase`; a bonus, not itemized in the audit). **Also retired IN-CAMPAIGN, off the audit list:** the invented multi-exit switch-decline heuristic (`7b6d36c`) and the three "heritage completes first" members (RuleEarlyRemoval's dropped `deadRemovalAllowedSeen` guard, ActionDeadCode's absent pre-live seeding, the mosura-INVENTED `heritage_complete` graph-shape predicate).

**STILL PRESENT — 13, verified on HEAD, and they are NOT independent (C1 GATES C2/D1/D3, so closing one unblocks three):**
· **G1** the up-front alias CLONE-PROBE — pipeline.rs:61-62, still labelled PROBE-DIAGNOSTIC; **now the highest-bite single item** (A3, its former peer, is done). Ghidra has NO probe: `AliasChecker::gather` runs from `ScopeLocal::restructureVarnode` on the real guarded graph. Its entanglement is already documented (the 135 unresolved placeholder aborts ARE the probe clone).
· **C-CLUSTER (3, the deep foundation):** **C1** `structure()` re-derived — now **20 call sites** (structure.rs 15, varmap.rs 4, printc.rs 1) vs Ghidra's ONE persistent mutating BlockGraph · **C2** `block_negate_condition` XOR-into-negated, not `FlowBlock::negateCondition` edge-reversal (gated on C1) · **C3** no persistent HighVariable — **7 `HighVariables::new` rebuild sites** in merge.rs.
· **B-CLUSTER (3, print-time vs IR-time):** **B1** `is_explicit` at print (Ghidra sets the flags in-IR: ActionMarkExplicit/MarkImplied, coreaction.cc:3007/3416) · **B3** print-time De Morgan (the MISSING ActionNormalizeBranches) · **B4** print-time `switch_index`/`case_labels` heuristics (→ BlockSwitch::getSwitchVarnode/getLabelByIndex).
· **D-CLUSTER (3, once-pass vs iterating, C1-coupled):** **D1** merge once at the pipeline tail (pipeline.rs:778) · **D2** addrtied re-derived by scanning, 4 sites, vs set-at-creation · **D3** OrientBranches/PreferComplement once-pass at the tail.
· **F (2):** **F1** RuleEqual2Zero's missing all-descendants-bool guard (switchloop currently DEPENDS on the extra firing — textbook masked-absence) · **F2** bool propagation approximating nzmask with width.
· **phi input slot order** by block-index instead of `addInEdge` temporal order.
· **Minors:** check_call_double_use within-block position; LaneDivide lanedMap re-derived.

**The risk-register framing is UNCHANGED and now has more evidence behind it** — this campaign has retired six inventions and every single one was masking something: XMM0:8 → merged cover · RAX:8 → narrow-switch recovery · RDI..R9:8 → the whole stack-trial subsystem · the multi-exit heuristic → destroyed WAR2 switches while corpus-inert · B2's double-declaration → **stayed legal C only because two name synthesizers disagreed about the stem** (an adaptation DEPENDING ON A SECOND BUG to remain valid) · `heritage_complete` → stopped the stack pass from ever running. **"Corpus-inert" has now failed as a safety signal six times out of six.**

## ⚠️ RE-VERIFIED AGAINST THE TREE 2026-07-29 @08ca850 (the audit body below is 2026-07-18 and partly stale)

**RETIRED since audit1** (checked at their sites today): **A1** — `sysv_input/output/effect_list` are now TEST-ONLY (fspec.rs:1096+ all inside `mod tests`); `ProtoModel` decodes from the cspec (analysis/cspec.rs:132, build.rs:34) ✅ · **A2** — return list `[(RAX,8),(XMM0,8)]` retired by the guardReturns port `6e1b113`; call list `RDI..R9` retired by Stage B `08ca850` (committed HELD) ✅ · **E1** — `normalize_read_size` is now a PER-RANGE fn called from `guard()` (heritage.rs:1671), batch gone ✅ · **E3** — retarget-to-unique replaced by Ghidra's write-masked shape (Stage A `e840e56`) ✅ · **E2** — Normalize mode retired by Stage A (`refine_overlaps` still called at heritage.rs:1904 for the faithful refinement).

**STILL PRESENT, verified at file:line today (~15):** A3 `RSP=0x20` (space.rs:108 — stackptr patch held) · B1 print-time `is_explicit` (printc.rs:217) · B2 stack naming/typing at print + spacebase getSubType stub · B3 print-time De Morgan (printc.rs:1183) · B4 print-time `switch_index`/`case_labels` (printc.rs:1599/1344) · **C1** `structure()` re-derived, 18 call sites (structure.rs:2889) · C2 block_negate XOR-not-edge-reversal · **C3** HighVariables rebuilt on demand (merge.rs:101/128/490/1274) · D1 merge once at tail (pipeline.rs:764) · D2 addrtied by scan · D3 OrientBranches/PreferComplement once at tail · **G1 the up-front alias CLONE-PROBE (pipeline.rs:61-67, still labelled PROBE-DIAGNOSTIC)** · F1 RuleEqual2Zero missing the all-descendants-bool guard · F2 bool propagation approximates nzmask with width · phi slot order by block-index not addInEdge order · minors (check_call_double_use, LaneDivide lanedMap).

**⭐ THE FRAMING CHANGED — THIS LIST IS A RISK REGISTER, NOT A BACKLOG.** Three measured instances this campaign (XMM0:8 → mixfloatint's merged cover · RAX:8 → narrow-switch recovery at 4 dispatch sites · RDI..R9:8 → piecestruct's 1-byte param AND the whole stack-trial subsystem) prove **an adaptation can MASK ITS OWN ABSENCE — minting correct output through a wrong mechanism.** ⇒ "corpus-inert / behavior-neutral" is NO LONGER evidence of harmlessness for ANY of the 15. Each is a place where a future faithful port will appear to REGRESS, and where a real defect may be hidden right now. **Highest bite-risk next: A3 (arch-hardcoded constant — the class that produced the 0% wall) and G1 (a non-Ghidra probe standing in for machinery Ghidra runs inline).**

audit1 read-only sweep @`a2211f3` (corpus 0.9480/57). Each item read at its site + verified against current code (not just memory). "Adaptation" = non-Ghidra code (heuristic/approximation/stand-in/hardcoded-list/wrong-stage/wrong-order). NOT adaptations: faithful cross-language translations, and dormant/incomplete faithful ports.

## A — hardcoded-list-vs-spec-derived (highest impact)
- **A1 ★ SysV param/return/effect lists HARDCODED, decompiler doesn't consume the faithful cspec loader.** fspec.rs:531 `sysv_input`/:576 `sysv_output`/:620 `sysv_effect_list` (offsets :518-526); consumed recover.rs:828, heritage.rs:1467, directwrite.rs:58, fspec.rs:837. Ghidra decodes from cspec XML (ParamListStandard::decode / ProtoModel::effectlist, fspec.cc:1451/1247). **A FAITHFUL cspec-XML decoder ALREADY EXISTS — `analysis/cspec.rs` (default_input_paramlist → same fspec::ParamList type) — but only symbolic.rs:163 uses it; decompiler still uses the literals. MEDIUM-BOUNDED: wire it in.**
- **A2 fixed return/call candidate lists (append-all-then-prune).** recover.rs:493 return `[(RAX,8),(XMM0,8)]`; :34 ARG_REGS=[RDI..R9] appended :623. Ghidra registers ONE trial/heritaged-range (guardReturns→characterizeAsOutput heritage.cc:1652). recover.rs:487 doc admits it. MEDIUM (single-trial model). **arg1 2026-07-19 NOTE: append-all is NOT a correctness bug for multi-call arg ATTRIBUTION — Ghidra also appends-all-then-trims (guardCalls per-range `opInsertInput`). The deindirect/indproto "args on wrong call" class was a re-frame: fixed by `sortCallSpecs` (call eval order = block-index/RPO), NOT by per-range registration. BUILT+GATED, see merge-family-cluster.md arg1. Do NOT re-open S1-S3 as a fix for that class.** The remaining A2 adaptation (fixed candidate LIST vs single-trial characterizeAsInputParam) is cosmetic/backlog, not corpus-affecting for this class.
- **A3 stackpointer RSP=0x20 hardcoded.** space.rs:105-108 (used build.rs:48). Ghidra reads `<stackpointer>` from cspec. x86-64-only → corpus-inert differential. BOUNDED low.

## B — print-time-vs-IR-time
- **B1 ★ explicitness RE-DERIVED at print (no ActionMarkExplicit/MarkImplied action).** printc.rs:223 `is_explicit` (core faithful via merge.rs baseExplicit/checkImpliedCover, + 3 printc-only arms force_explicit:229/slot_write:236/high_ram_off:246). Ghidra sets Varnode explicit/implied flags in-IR (coreaction.cc:3007/3416). IN-PROGRESS retirement (explicit1). MEDIUM.
- **B2 stack-symbol naming/typing deferred to print; getSubType spacebase STUB.** types.rs:125 Spacebase→Unknown(1) stub; recover_scope re-derived infertypes.rs:177/ptrarith.rs:483/printc.rs:1869. Ghidra TypeSpacebase::getSubType resolves real ScopeLocal type in-IR (type.cc:2947). MEDIUM/DEEP.
- **B3 print-time De Morgan distribution.** printc.rs:1183 (BoolAnd/Or, gated op_flip_normalizes) — `!(a&&b)⇒!a||!b` at print for non-materialized compound leaves (nan). Ghidra materializes in-IR (ActionNormalizeBranches MISSING). (`==↔!=` token flip in same fn IS faithful = negatetoken.) LOW/bounded.
- **B4 print-time switch heuristics for UNnormalized tables.** printc.rs:1504-1517 switch_index bound-scan + :1573 case_labels 0-based fallback. Ghidra BlockSwitch::getSwitchVarnode/getLabelByIndex. (Normalized tables already faithful via folded BRANCHIND.) LOW-MEDIUM.

## C — re-derive-vs-persist (no persistent structure objects) — the DEEP foundation
- **C1 ★ `structure()` re-derived from CFG each call — no persistent BlockGraph (P7 "gap B").** structure.rs:2889, 3× (printc.rs:1927, OrientBranches :3038, PreferComplement :3072). Ghidra: one persistent mutating BlockGraph (ActionBlockStructure). Inert on corpus but blocks faithful edge-reversal. DEEP/broad.
- **C2 block_negate_condition XOR-into-negated not edge-reversal** (consequence of C1). funcdata.rs:681. Ghidra FlowBlock::negateCondition reverses out-edge order. DEEP (needs C1).
- **C3 no persistent HighVariable — merge state re-derived read-only.** merge.rs (all_covers+HighVariables rebuilt on demand; process_copy_trims :884 re-derives full state each iter). Ghidra: one live incremental HighVariable/Merge graph. Blocks Ghidra's incremental speculative merges. DEEP/broad, behavior-neutral today.

## D — once-pass-vs-iterating & ordering
- **D1 merge phase once at pipeline tail.** mergesnip.rs:19, pipeline.rs:737-758. Ghidra: merge actions in the repeating structure. MEDIUM/DEEP (mainloop-repeat).
- **D2 addrtied re-derived by scanning not set-at-creation (double/multi-mark).** varnodeprops::mark_addrtied at pipeline.rs:319/:358/:737. Ghidra sets addrtied at creation. BOUNDED, behavior-neutral.
- **D3 OrientBranches/PreferComplement once-pass at tail.** structure.rs:3020 (self-described approximation), pipeline.rs:723-730. Coupled to C1.

## E — pass-0 batch heritage (interim; faithful re-entry path exists)
- **E1 normalize_read_size pass-0 batch.** heritage.rs:265 wired :1591. Faithful normalize_ranges covers only re-entry; first-pass still batch. Corpus-affecting; task#6/#8-coupled. DEEP.
- **E2 refine_overlaps pass-0 batch (XMM-laned only, GP-partition skipped).** heritage.rs:1078 wired :1586. Faithful all-space refine_ranges is re-entry-only. DEEP.
- **E3 normalize_write_size retargets op to a unique temp.** heritage.rs:702 (self-labeled adaptation). Ghidra keeps original narrow vn + write-mask. Documented behavior-equiv. LOW/candidate.

## F — rule/behavior divergences
- **F1 RuleEqual2Zero omits the all-descendants-bool-output guard.** rules.rs:1108 (fires broader than Ghidra). switchloop jumptable recovery DEPENDS on the extra firing (separate switch-path IR divergence). BOUNDED but gated.
- **F2 bool propagation approximates nzmask with width.** infertypes.rs:305/:591. Ghidra: bool only if provably 0/1 (nzmask). BOUNDED (needs nzmask at type-inference).

## G — up-front alias probe
- **G1 up-front clone-probe for pass-0 alias boundary.** pipeline.rs:56-72 (clones fn, fully simplifies clone, runs AliasChecker for pass-0 alias_boundary that guard_calls consumes). Ghidra has NO probe (guardCalls per ProtoModel effect list; AliasChecker in ActionRestructureVarnode). Per-iteration recompute IS faithful now (Brick D); only pass-0 uses the probe. DEEP.

## Minor/candidate
- check_call_double_use within-block position for getSeqNum().getOrder() (recover.rs:232, no global op order). LOW.
- LaneDivide lanedMap re-derived from live varnodes (lanedivide.rs:698). behavior-equiv. LOW.
- **phi input slot order = ascending predecessor block-index** (cfg.rs:282-286; phi slot j = heritage.rs:1884). Ghidra in-edge (`intothis`) order = the **`addInEdge` temporal sequence** (block.cc:73), NOT ascending index and NOT RPO — `findSpanningTree` (block.cc:1009) only sets the block INDEX (dominators), never reorders intothis. mosura's block-index re-sort at cfg.rs:282-285 discards edge-add order → the switchloop case-2 root (case-2 in_edge before case-4; Ghidra has case-4 THEN case-2-last from reverse recoverJumpTables append). **← rpo1 campaign (2026-07-19, re-frame #18) retiring THIS: corrected target = faithful in_edge CONSTRUCTION ORDER (connectBasic add-order + two-phase iterative-recovery timing), NOT a block-index RPO renumber (that's a forbidden proxy). C1 NOT a prerequisite; deep fallback = iterative followFlow/recoverJumpTables edge-generation. Blast proven bounded to switchloop. See [[finish-parked-before-new]].**

## Verified RETIRED (confirmed gone on HEAD)
consume→~0 (`608d7d3`); is_return_value_use any-slot; recover_return XMM0:4 sibling + is_const_padded_piece; print-time stack naming (anchor_stack_arrays/stack_addr); if_else_flip / render_negated ≤/< reorder-increment; stackvars general stack LOAD/STORE resolution (#22-B); "no ActionDirectWrite" (directwrite.rs); rule_goto/trace_dag_placeholder (P7). build.rs multistage jumptable recovery = now FAITHFUL (FlowInfo::recoverJumpTables), NOT an adaptation; residual table_recovery_probe = minor consequence-gate.

## Dormant/incomplete faithful ports (NOT adaptations)
analysis/cspec.rs (faithful cspec decoder, unwired for decompiler = A1's ready replacement); RuleSubvarSext/RulePtrFlow (subvarflow.rs:1174 stubbed); coverage.md MISSING list (RuleLoad/StoreVarnode stack-spacebase branch S2, guardLoads/discoverIndexedStackPointers, isUnmappedUnaliased varmap.cc:494, RulePtraddUndo/PtrsubUndo, SplitDatatype).

**Highest-value retirements:** A1 (wire existing cspec loader — replacement already built) · A2 (single-trial characterize) · E1/E2 (first-pass heritage batch) · G1 (alias probe) · the C-cluster (persistent BlockGraph/HighVariable = the deep structural foundation).
