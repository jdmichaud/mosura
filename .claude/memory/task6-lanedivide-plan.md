---
name: task6-lanedivide-plan
description: "Task #6 COMPLETE + LIVE (reactivated `2993771` 2026-07-16, pre-pool slot). ml8f 2026-07-17: the stackstall-slot move (task #8 Brick F) BUILT — premise confirmed (concatsplit picks 8-byte lanes = Ghidra-exact at the faithful slot) but RECOMMENDED-PARK on wrong-code (lane stores die vs the missing stack-range refinement partition); patch parked, see ★★★ section + [[task8-mainloop-repeat]]."
metadata:
  node_type: memory
  type: project
  originSessionId: c0fe6b35-0fb2-4ed2-90d8-ec93de63680c
---

Task #6 = port Ghidra **ActionLaneDivide** (laned-vector split) to fix stackstring (0.794).
Owner lane1, PARALLEL worktree `/home/jd/projects/mosura/mosura-lane` branch `lanedivide`
(base master `91ddcf7`; sb3 works main checkout — NEVER touch it). See [[direction-faithful-port]],
[[port-all-faithful-rules]].

## BASELINE (base `91ddcf7`, worktree lanedivide)
suite **350/0**; corpus stackstring **0.794** (avg ~0.8936 per prior memory; report prints
per-fixture only, no avg line). Oracle scoring in the worktree needs the binaries symlinked:
`ln -sf /home/jd/projects/mosura/mosura/oracle/capture{,_trace} oracle/` (gitignored, `!!`).
Per-fixture mosura dump: `cargo run -q --example dumpc -- <stem> [--raw]`. Oracle stage IR:
`oracle/capture <ghidra_root> <fixture.xml> --ir <action>` breaks at START of <action>
(`--ir -` = final, `--ir lanedivide` = before it runs, `--ir multicse` = right after it).

## PHASE-1 GROUNDING — DONE (2026-07-09, all read-only; probe zz_laneprobe.rs deleted, tree clean)

### The subsystem (line-cited)
- **ActionLaneDivide**: coreaction.cc:585 apply / :558 processVarnode / :500ish collectLaneSizes;
  decl coreaction.hh:113; `rule_onceperfunc`. Registered coreaction.cc:**5652** in the `actstackstall`
  group of the mainloop (after `actprop`=oppool1, before ActionMultiCse/ActionDeindirect/
  ActionStackPtrFlow). apply() loops mode 0/1/2 over `lanedMap`; per storage, per varnode →
  processVarnode → collectLaneSizes(SUBPIECE-out-size / PIECE-in-size) → LaneDescription(whole,lane)
  → LaneDivide.doTrace()→apply().
- **LanedRegister** (transform.hh:94): source = pspec `vector_lane_sizes` attr on `<register>`
  inside `<register_data>` (x86-64.pspec:79 ZMM0 / :111 YMM0 / :143 XMM0, all `"1,2,4,8"`) →
  **3 records keyed by SIZE: 16(XMM)/32(YMM)/64(ZMM), lane mask {1,2,4,8}**. Parsed
  architecture.cc:929 decodeRegisterData; getLanedRegister(architecture.cc:290) is **SIZE-keyed only**
  (ignores address — any register-space vn of size 16/32/64 matches). minLanedSize gates. lanedMap
  filled at VARNODE CREATION: funcdata_varnode.cc:90/298 checkForLanedRegister→getLanedRegister.
  **mosura does NOT parse the pspec** (grep-confirmed) — it hardcodes `XMM_BASE=0x1200` in
  heritage.rs:464 + fspec.rs:523. So mosura needs a lane-info source: either add minimal
  `vector_lane_sizes` pspec parsing, OR hardcode a size→lanemask table {16,32,64}→{1,2,4,8} for
  x86-64 (size-keyed, tiny). LEAD DECISION.
- **LaneDivide** (subflow.hh:426, subflow.cc:3518-4128) : public TransformManager. WorkList of
  (lanes,numLanes,skipLanes). doTrace→processNextWork→traceBackward(def)+traceForward(descends).
  build* per opcode: buildStore(3704, splits STORE into per-lane STOREs w/ INT_ADD +offset pointer),
  buildPiece/Multiequal/Indirect/Load/RightShift/LeftShift/Zext, buildUnary/BinaryOp. traceForward
  handles SUBPIECE(restriction/downcast-terminator)/PIECE/COPY/NEGATE/AND/OR/XOR/MULTIEQUAL/INDIRECT/
  INT_RIGHT/STORE. traceBackward handles COPY/NEGATE/AND/OR/XOR/MULTIEQUAL/INDIRECT/SUBPIECE/PIECE/
  LOAD/RIGHT/LEFT/ZEXT.
- **TransformManager/TransformVar/TransformOp/LaneDescription** base: transform.hh + transform.cc
  (whole file 24-767). apply() = createOps→createVarnodes→removeOld→transformInputVarnodes→
  placeInputs. TransformVar types {piece,preexisting,normal_temp,piece_temp,constant,constant_iop}.
  **SplitFlow (subflow.hh:221) ALSO extends TransformManager** → the framework is shared (unlocks
  SplitDatatype/SplitFlow + SubfloatFlow later, per lead). Port it as the GENERAL framework.

### mosura has / lacks
- HAS Funcdata prims: new_unique, set_input_varnode, delete_varnode, op_insert_before,
  op_insert_begin, op_destroy.
- LACKS (must add for framework): new_unique_out, new_varnode_out, new_varnode_iop,
  transfer_varnode_properties, mark_indirect_creation, new_constant (as a Funcdata method).
- **mosura's INDIRECT is 1-INPUT (no iop)** — funcdata.rs:413. LaneDivide.buildIndirect uses
  newIop for input(1). buildIndirect needs a mosura-1-input adaptation (or skip when unreached).
- HAS a laned ADAPTATION `refine_overlaps` (heritage.rs:457, XMM_BASE=0x1200): at HERITAGE time it
  Normalizes 16-byte-XMM sub-reads to SUBPIECE-of-whole (faithful to Ghidra guard/normalizeReadSize)
  and Refine-partitions laned ranges no single write covers. This produces the pre-lanedivide
  SUBPIECE Ghidra also has — it SETS UP LaneDivide, does NOT block it, does NOT need canceling here.

### stackstring instrument (the exact shapes)
- Oracle BEFORE lanedivide: `XMM0:10(free) = r0x100250:10` ; `*(ram,RSP)=XMM0` (16B STORE) ;
  `XMM0_Qa = SUB168(XMM0,#0)` (8B). Root XMM0 = 16B, 2 lanes of 8.
- Oracle AFTER lanedivide: `XMM0_Qa=r0x100250`, `XMM0_Qb=r0x100258` (traceBackward split the COPY of
  the free ram read); STORE split (buildStore) → `*(ram,RSP)=Qa` + `u=RSP+0x8` + `*(ram,RSP+8)=Qb`;
  the SUBPIECE → COPY from Qa.
- Oracle FINAL / C: `s-0x28=r0x100250(i); s-0x20=r0x100258(i)` → `xStack_28=xRam..100250;
  xStack_20=xRam..100258;` (2 lane stores become 2 stack slots via RuleStoreVarnode).
- mosura at the Ghidra-position (post-oppool1): `s0x..d8:16 = INDIRECT r0x100250:16` — laned register
  already FOLDED AWAY by pre-pool recover_stack + pool copy-prop; printc drops it (refs &xStack_28,
  never assigns). = the bug.

### ★ KEY ORDERING FINDING (drives placement) ★
mosura resolves stack stores PRE-POOL (`recover_stack` runs INSIDE ActionHeritage's first call,
pipeline.rs:47) and the first `default_rule_pool` copy-propagates the laned register away. So at
Ghidra's literal stackstall position (after oppool1) there is NO live laned register to divide.
BUT at **post-heritage / pre-pool** mosura STILL has it live (probe zz_laneprobe, deleted):
  `r0x1200:16 = COPY r0x100250:16`  (XMM0=reg 0x1200, 16B laned)
  `u0xd700:16 = COPY r0x1200:16` → `s0x..d8:16 = COPY u0xd700:16`  (the store, now a slot-COPY chain)
  `u0x10002:8 = SUBPIECE r0x1200:16 #0` (+ an extra 4B SUBPIECE → forces mode-1 downcast)
This is the shape LaneDivide needs. **PLACEMENT = right after heritage completes, BEFORE the first
default_rule_pool.** LaneDivide then splits r0x1200→Qa/Qb, traceBackward splits the ram read, and
traceForward through the COPY chain splits the 16B stack slot into s-0x28:8 + s-0x20:8 — matching
Ghidra's data flow even though the pipeline slot differs (Ghidra hasn't stack-resolved yet there;
mosura already has, but the slot-COPY is still splittable via the COPY path). This is a
faithful-behavior placement, NOT the literal registration order — flag to lead.

## STAGING PROPOSAL (reported to lead 2026-07-09, WAIT for go) — JumpBasic-style, each gated
- **S0 lane-info source** (LEAD DECISION): minimal pspec `vector_lane_sizes` parse vs hardcoded
  size→{1,2,4,8} table for x86-64. Size-keyed getLanedRegister + minLanedSize gate + checkForLaned
  hook at varnode creation (or a scan at apply()).
- **S1 TransformManager framework** (transform.hh/cc port) as its OWN stage — byte-identical/unwired,
  unit-tested. TransformVar/TransformOp/LaneDescription + apply() pipeline + the missing Funcdata
  prims (new_unique_out/new_varnode_out/new_varnode_iop/transfer_varnode_properties/
  mark_indirect_creation/new_constant). General framework (unlocks SubfloatFlow+SplitDatatype later).
- **S2 LaneDivide** (subflow LaneDivide subclass) HELD/unwired + unit-tested (synthetic 16B-XMM
  split). Handle the 1-input INDIRECT wrinkle in buildIndirect.
- **S3 ActionLaneDivide + wire GATED** at post-heritage/pre-pool (NOT Ghidra's stackstall slot — see
  ordering finding). Expect stackstring split lands (xStack_28/xStack_20 assigned). Gate: full corpus
  per-fixture delta + rebase onto current master + WAIT for lead go before merge.

## LEAD DECISIONS (2026-07-09) — GO S0+S1
- **S0 = MINIMAL PSPEC PARSE** (NOT hardcoded table — a table would be a Phase-4 multi-arch adaptation
  to cancel). Read `<register_data>` `<register vector_lane_sizes=...>` from x86-64.pspec
  (:79/111/143), resolve name→size via mosura's sleigh register table, build size-keyed map matching
  architecture.cc:290 getLanedRegister semantics (maskList[size] |= mask, architecture.cc:958-973).
  Cite pspec lines + getLanedRegister in code.
- **PLACEMENT post-heritage/pre-pool APPROVED** with DOC DUTY at the wire + coverage.md ActionLaneDivide
  row + this memory: (a) Ghidra's literal slot = stackstall post-oppool1; (b) mosura places pre-pool
  because stackvars resolves earlier (the pipeline-shape approximation family, FORCED not chosen);
  (c) LINKAGE — when stackvars timing is replaced by faithful spacebase/StackPtrFlow (backlog),
  re-evaluate moving to Ghidra's slot.
- **S2 buildIndirect iop**: sb3 is landing `guarded_op: Option<OpId>` on PcodeOp on master NOW (iop-1/
  iop-2). After rebase I'll HAVE it — use THAT for buildIndirect's iop, NOT a local adaptation. If I
  reach S2 before it lands: leave a TODO-on-rebase.
- Staging approved as proposed: S0 → S1 (the strategic framework base) → S2 (LaneDivide HELD) → S3
  (wire gated, full delta + rebase + WAIT).

MERGE to master is LEAD-GATED (worktree). Commit freely on branch at green boundaries; suite green
every commit; coverage.md flips on branch; NEVER `git add -A`; trailer Co-Authored-By Claude Fable 5.

## PROGRESS
- 2026-07-09: Phase-1 grounding done + reported. Lead GO'd S0+S1. Base 91ddcf7 (will rebase for
  sb3's guarded_op before S2/S3).
- **S1 LANDED `318836b`** (branch lanedivide): new `transform.rs` = full TransformManager framework
  (TransformVar/TransformOp/LaneDescription/LanedRegister + apply pipeline createOps→createVarnodes→
  removeOld→transformInputVarnodes→placeInputs). + 2 Funcdata prims (transfer_varnode_properties,
  mark_indirect_creation). Arena-indexed (TVarId/TOpId) since Rust can't do Ghidra's raw-pointer
  `rvn+i` — a split's lanes are contiguous so `rvn+i`=TVarId(base+i). LE-only (big-endian reorder +
  renormalize omitted, subvarflow convention). constant_iop createReplacement = `unimplemented!`
  pending S2 buildIndirect over guarded_op. BYTE-IDENTICAL (unwired), suite 358/0 (350+8 tests:
  LaneDescription/LanedRegister pure + apply() splitting a 16B COPY into 2×8B lanes). coverage.md
  ActionLaneDivide row + SubfloatFlow note updated (base now ported).
  KEY MAPPINGS: Ghidra newUniqueOut→mosura new_output_unique; newVarnodeOut→new_output;
  newConstant→new_const. removeOld = op_destroy + op_uninsert (Ghidra opDestroy removes from block).
  createReplacement preexisting-op: op_set_opcode + place_inputs op_set_all_input (subsumes Ghidra's
  opUnsetInput/opInsertInput reshaping). new-op: new_op(empty inputs) then place_inputs sets them.
- **S0 LANDED** (was `d1d4c84`, now `2b49502` post-rebase): pspec `vector_lane_sizes` parse.
  transform.rs `LanedRegisterSet` (size-keyed, get_laned_register binary-search, minimum_laned_size).
  lang.rs `pspec_laned_registers` (roxmltree parse `<register_data>`, resolve name→size via
  `Spec::register_size`). engine.rs `Spec::register_size(name)`. Test parses real x86-64.pspec →
  {16,32,64}→{1,2,4,8}, min 16. BYTE-IDENTICAL (unwired). NOTE: LanedRegisterSet not yet threaded
  into Funcdata/build — that's S3 (Funcdata field + build population + ActionLaneDivide query).
- **REBASED onto master f3eff2a** (2026-07-09): branch lanedivide now = f3eff2a + S1 `c65b2cd` + S0
  `2b49502`. Clean (no conflicts). sb3's `guarded_op: Option<OpId>` on PcodeOp NOW AVAILABLE (op.rs;
  commits e97e4fe iop-1, 7760c3b iop-2, f3eff2a B-ii). Suite 360/0. NEW corpus baseline (my delta
  reference): stackstring 0.794, partialmerge 0.786, impliedfield 0.921, avg 0.8918 (59 scored).
- **S2 LANDED `7d3fb71`**: new `lanedivide.rs` = LaneDivide (subflow.cc:3518-4128) full port —
  setReplacement + build{Piece,Multiequal,Indirect,Store,Load,RightShift,LeftShift,Zext,Unary,Binary}
  + traceForward/traceBackward/processNextWork/doTrace/apply. Composes TransformManager (`tm` field;
  disjoint field borrows work — `self.tm.method(&self.description)`). buildIndirect uses mosura's
  1-input INDIRECT + guarded_op (NOT Ghidra newIop). Framework extended: TransformOp gained
  `guarded_op` field (set on replacement in create_op_replacement new-op path) + op_set_guarded +
  inherit_indirect (isIndirectZero→conservative possible_out, inert on corpus). typelock guard:
  mosura metatype REVERSED (primitives < Array=6 < Struct=7) → reject if `meta < 6 || meta == 7`.
  STORE space-const = SpaceId value; LE lane order. HELD/unwired, byte-identical (stackstring 0.794),
  suite 362/0. 2 tests (16B laned COPY+STORE → 2×8B lane stores at ptr/ptr+8; downcast gate).
- **S3a LANDED `73bd676`**: ActionLaneDivide (coreaction.cc:585 processVarnode mode 0/1/2 +
  collectLaneSizes + apply-loop) + scan-at-apply lanedMap (collect_laned_accesses, deduped register
  varnodes of laned size w/ descendants) + WIRE at post-heritage/pre-pool (pipeline.rs:372, before
  first default_rule_pool). INERT until Funcdata.laned populated (early-return on is_empty).
- **S3b (2026-07-10) — LIVE WIRE DONE + MEASURED; MOVER BLOCKED, HELD, awaiting lead gate.**
  Baseline discrepancy RESOLVED first: the predecessor's "59 scored/0.8918" was a TRANSIENT oracle-cache
  miss on the cold `build/oracle-cache` of the fresh worktree (oraclecache.rs:47 doesn't cache failed
  captures → self-heals). Now deterministic **62/62 decompiled, 60 scored, avg 0.8936** = master canonical.
  S3b plumbing (5 files, UNCOMMITTED on branch, HEAD still 73bd676): `Spec.laned: Vec<(i32,u32)>`
  primitive size→mask pairs (engine.rs — kept primitive so sleigh needs NO decompile-type edge);
  loader populates from the DEFAULT pspec — speccache.rs + lang::load via new `lang::default_pspec_for_sla`
  (reverse ldefs lookup, prefer `:default`; x86-64.sla is shared by default+compat32 but laned regs are
  the same physical XMM/YMM/ZMM) + `lang::pspec_laned_size_masks`; build_from_instrs wraps into
  `f.laned = LanedRegisterSet::from_size_masks(...)` (4 call sites pass &spec.laned); dumpc switched to
  speccache::get so it sees laned. Suite **363/0 GREEN** live (ir_parity fixtures = sem/elseif/twodim/
  threedim/ifswitch/condconst, none vector-laned, so the hard gate is untouched). Placement = mosura's
  Architecture analog is Spec (owns register_size); faithful (like ctx-provisioning, active by default).
  ★ FINDING — MOVER BLOCKED by an UPSTREAM (P6) gap, NOT a lane-divide bug: lane division fires on
  stackstring (accesses=[(0x1200,16)], count=1) but SPLITS XMM INTO 4-BYTE LANES where Ghidra uses
  8-byte. Cause: mosura has spurious **4-byte** XMM SUBPIECEs at lanedivide time that Ghidra lacks
  (stackstring: `u0x1000a:4 = SUBPIECE r0x1200:16` at the RETURN alongside the real 8-byte one — an
  output-characterization TRIAL; Ghidra's pre-lanedivide IR has ONLY `XMM0_Qa = SUB168(XMM0,#0)`, the
  8-byte call-arg). Ghidra's collectLaneSizes (coreaction.cc:509) registers each SUBPIECE-descendant's
  OUTPUT size and processVarnode tries them SMALLEST-FIRST (mode 0) — so given a 4-byte SUBPIECE Ghidra
  would ALSO pick 4; my port is faithful, the divergence is purely the extra 4-byte read. TWO mosura
  causes stack: (a) P6 output/param recovery creates 4-byte XMM trials (task2-p6 "characterizeAsOutput
  over-widen"); (b) the pre-pool placement retains trials NOT-YET dead-code-eliminated (Ghidra's
  stackstall lanedivide runs AFTER oppool1+deadcode, so its trials are gone). Tested post-pool placement
  → laned reg copy-propagated away (confirms the KEY ORDERING FINDING), NO split at all. So NEITHER
  placement is clean for mosura (pre-pool = live reg + dead trials; post-pool = clean but reg folded).
  DELTA (60 scored): stackstring 0.794 UNCHANGED (blocked); floatcast 0.804→0.842 (+); floatprint
  1.000→0.973 (−, 8-byte store split into two 4-byte); concatsplit 0.881→0.863 (−, CONCAT44 pairs
  split into 4-byte stores); avg 0.8936→**0.8935** (flat-negative). RECOMMENDATION (reported to lead,
  awaiting gate): HOLD the live wire — do NOT merge; the faithful framework (S1 c65b2cd/S0 2b49502/S2
  7d3fb71/S3a 73bd676) stays committed + inert; the real unblock is P6 (task #4: stop the 4-byte XMM
  output/param trials) and/or the faithful spacebase/StackPtrFlow model (moves stack resolution
  post-pool → Ghidra's stackstall slot becomes usable). Task #6's lane-divide port itself is COMPLETE
  and faithful; it's blocked on an upstream dependency, same pattern as #4→#10.
## ★ RE-MEASURED ON CURRENT MASTER `b573e78` (2026-07-11, p4infer1, task #15, throwaway probes ALL REVERTED → tree clean) — the "floatcast +0.038 at reactivation" claim is STALE/master-dependent; premise FALSIFIED on 0.9209
Task #15 = "P6 4-byte-XMM-trial fix → LaneDivide reactivation (floatcast +0.038 lever)". I re-ran the reactivation experiment on b573e78 (master avg **0.9209**, floatcast **0.776** post-#12's −.028). Three throwaway measurements (speccache::get uncomment + recover.rs XMM0:4 retire, reverted):
- **A** LaneDivide reactivated, XMM0:4 PRESENT: floatcast 0.776→**0.774** (flat), floatprint 1.000→**0.850** (−.150), concatsplit 0.881→0.863, avg **0.9180** (−.0029). (matches p6b1)
- **B** LaneDivide reactivated + XMM0:4 RETIRED: floatcast **0.774** (STILL FLAT — NOT +0.038), floatprint **1.000** (recovered — XMM0:4 retire fixes its lane block), concatsplit 0.863 (−.018 STILL), avg **0.9205** (−.0004). (matches p6b1)
- **C** XMM0:4 RETIRED only (LaneDivide inert): **BYTE-IDENTICAL** 0.9209 (confirms XMM0:4 = dead-weight overlapping candidate, only creating the blocking 4-byte SUBPIECE).
CONCLUSION: The task#6 S3b "floatcast +0.038" was on the OLD 0.8936 master; it does NOT reproduce on 0.9209 (#7-#12 changed floatcast's baseline+IR, esp. #12 isSubpieceCast). **The P6 4-byte-trial fix (retire XMM0:4) is bounded+faithful+byte-identical AND fixes floatprint's would-be lane block — but it does NOT unblock floatcast.** Floatcast C under B: LaneDivide DID clean the middle arithmetic (`fVar1 = fRam..80 - fRam..88`, clean float8, no 16-byte CONCAT88) but TWO residual blockers keep it flat, NEITHER a P6 trial: (1) **return-value 16-byte XMM assembly** still `(xunknown8)CONCAT124((xunknown12)(CONCAT88(0,fVar1)>>0x20),(float4)fVar1)` vs Ghidra clean `CONCAT44(...)` — LaneDivide do_trace doesn't split the RETURN construction (task #6 do_trace/placement); (2) a **global-vs-local** artifact (mosura writes `fRam..80=(float8)param_1`, Ghidra uses local `fVar1` — spacebase/forwarding). Plus concatsplit −.018 (genuine live 4-byte over-split, task #6 do_trace). So the floatcast lever needs task #6 do_trace work (return-split + placement), NOT just the P6 trial. Reported to lead as premise-falsified STOP; recommend either land XMM0:4 retirement as the faithful single-trial characterizeAsOutput cleanup (byte-identical, unblocks floatprint at future reactivation) or redirect. See [[task2-p6-prototypes-plan]] Sub-part 2, [[faithful-type-of-wrong-ir]].

## ★★ DEEP-FLOAT STAGING GROUND (2026-07-11, p4infer1, task #15 = user-picked deep float; READ-ONLY probes reverted, tree clean b573e78) — floatcast RETURN-split is the PLACEMENT/mainloop-repeat rock, NOT a boundable do_trace extension
Grounded the lead's 4 pieces (single-trial cleanup / do_trace return-split / reactivation / global-forwarding) to propose staging. VERDICT: only piece 1 is bounded; pieces 2–4 are BLOCKED on the LaneDivide placement rock (= task #7 S2 spacebase post-pool stack-resolve OR task #8 mainloop-repeat).
- **PIECE 2 ROOT PINNED (the core floatcast blocker):** Under reactivation (measurement-B config), LaneDivide DOES split the arithmetic XMM0→8-byte (`r0x1200:8=MULTIEQUAL`, `u0x100d8:8=FLOAT_SUB r0x1200:8 r0x1280:8` clean), but the RETURN-value `r0x1200:16 = PIECE #0x0:8 u0x100d8:8` (zero-extend 8B diff into 16B XMM0) STAYS 16-byte → the pool then builds a non-lane 12-byte SUBPIECE chain (`INT_RIGHT r0x1200:16 #0x20` → `SUBPIECE :12` → `CONCAT124`) → `(xunknown8/12)`. Ghidra builds the return decomposition on the 8-byte lane → clean `CONCAT44((int4)((uint8)diff>>0x20),(float4)diff)`. WHY LaneDivide declines the return-side r0x1200: at LaneDivide time it's read directly by the RETURN op, and `traceForward` hits `default: return false`. ★ GHIDRA'S `LaneDivide::traceForward` (subflow.cc:3916) ALSO does `default: return false` and does NOT handle CPUI_RETURN — mosura's decline is FAITHFUL. The divergence is pure ORDERING: Ghidra's mainloop narrows XMM0→XMM0_Qa BEFORE the return CONCAT44 decomposition is built (returnrecovery + LaneDivide at stackstall, iterating); mosura's single-pass pre-pool LaneDivide declines the RETURN-read, then the pool builds the decomposition on the un-narrowed 16-byte reg. Adding a RETURN case to traceForward = non-faithful (Ghidra lacks it). So piece 2 is NOT boundable — it's the KEY ORDERING FINDING = task #8 mainloop-repeat / task #7 S2 post-pool stack-resolve.
- **PIECE 1 (retire XMM0:4 via single-trial characterizeAsOutput):** BOUNDED-FAITHFUL, byte-identical (measurement C). Removes the non-faithful overlapping candidate + fixes floatprint's would-be lane regression at future reactivation. Does NOT move floatcast. Fully-faithful form = characterizeAsOutput-derived single output trial replacing recover.rs:488's 3 fixed candidates (P6 port; scope sub-step needed — minimal = drop XMM0:4, full = single-output-trial model). Landable NOW independently.
- **PIECE 3 (reactivation):** trivial 2-line flip; net −.0004 best-case (measurement B) until piece 2 → can't land as a mover while blocked.
- **PIECE 4 (global-vs-local `fRam..80=(float8)param_1`):** reactivation-INTRODUCED (baseline uses local `uVar1`); entangled with piece-2 ordering + the spacebase track (task #7, held on mainloop-repeat). Deep.
CONCLUSION reported to lead: the floatcast win = the mainloop-repeat/spacebase-S2 foundation (task #8 / #7 S2), NOT deliverable on the current single-pass architecture. Only piece 1 is bounded (byte-identical, doesn't move floatcast). Staging proposal + this rock-identification sent; awaiting lead/user decision. See [[task8-mainloop-repeat]], [[task-sb-spacebase-placeholder]], [[faithful-type-of-wrong-ir]].

- **COMPLETE-INERT — LANDED `19bd978` (branch lanedivide, 2026-07-10).** Lead disposition (a): land the
  S3b plumbing INERT. Diff (5 files): `Spec.laned: Vec<(i32,u32)>` primitive pairs (engine.rs);
  `lang::pspec_laned_size_masks` + `lang::default_pspec_for_sla` (reverse ldefs `:default` resolver,
  TESTED — the reactivation mechanism); build_from_instrs threads `&spec.laned`→`f.laned` (empty ⇒
  inert); `speccache::get` + `lang::load` carry the HELD-INERT doc comment naming BOTH reactivation
  triggers + measured evidence (re-add the 2-line populate to reactivate); coverage.md ActionLaneDivide
  row → PORTED-INERT. Suite **364/0** (added default_pspec_for_sla test), corpus **byte-identical
  62/62 avg 0.8936**, jumptable 6/6. ★ REACTIVATION (when P6 lands or spacebase moves stack-resolve
  post-pool): uncomment `s.laned = pspec_laned_size_masks(&default_pspec_for_sla(path)?, &s)` in
  speccache::get (+ mirror in lang::load). At reactivation, `floatcast` +0.038 confirms the split is
  correct once fed correct-width reads; expect stackstring 0.794→UP only AFTER the 4-byte trials are
  gone. MODIFIED FINISH LINE (lead): I did NOT merge (sb5 holds main-checkout WIP; lead merges lead-side,
  branch files disjoint); worktree `/home/jd/projects/mosura/mosura-lane` REMOVED (branch lanedivide
  KEPT at 19bd978). Two-agent setup ends here; no replacement agent for task #6.

## ★★★ STACKSTALL-SLOT MOVE (task #8 Brick F) BUILT + RECOMMENDED-PARK (ml8f 2026-07-17 @608d7d3 — full gate record in [[task8-mainloop-repeat]] ★★★★★ section; patch `brickF-lanedivide-stackstall.patch` in memory dir)
The KEY ORDERING FINDING above is RESOLVED post-Brick-D (recover_stack retired): at Ghidra's stackstall slot (mainloop, directly after oppool1, OncePerFunc) the laned register is NO LONGER folded away on concatsplit — mosura's graph there is Ghidra-EXACT (one XMM0:16=CONCAT88, candidates=[8], splits 8; the spurious 4-byte call-arg SUBPIECEs fold in oppool1 exactly as Ghidra's). The old "post-pool = reg folded" claim now holds ONLY for ram-sourced laned values (stackstring): mosura's up-front full-heritage makes the ram read heritage-known → copy-prop folds XMM0 pre-slot (Ghidra's iter-1 lanedivide sees the ram read still FREE — per-iteration heritage passes). PARK REASON = wrong-code on concatsplit: the split lane STOREs die against the 16-byte re-load (missing stack-range refinement partition, heritage.cc:2610 domain + D1 alias-clear) — a class already present one-lane at baseline. PARK LEAD-CONFIRMED; patch re-verified applying clean on `1a405b0` (C2 landed). UNPARK = the stack-range refinement brick (grounded BOUNDED in [[task8-mainloop-repeat]] ★★★★★: widening-scoped all-space refine_ranges, helpers already ported in refine_overlaps) — land it first (it also heals the baseline one-lane loss), then re-probe F. stackstring −0.076 = Brick-E-adjacent heritage-cadence, score-only, does NOT block re-land. LaneDivide port itself stays COMPLETE + LIVE at the pre-pool slot.

## ★★ FLOATCAST LEVER = SplitFlow, NOT LaneDivide (mloop5, 2026-07-11, re-frame #6 — see [[task8-mainloop-repeat]] for the full record)
The floatcast return CONCAT44 is built by oppool1 SubVariableFlow-family RULES (RulePiece2Zext + RuleSplitFlow), NOT LaneDivide. Ghidra trace: lanedivide (DEBUG 126) fires ONCE and only rewrites the input-param `SUB164→XMM0_Da` extract; the return XMM 16→8 narrowing is splitflow (DEBUG 36) + piece2zext + pullsub_multi, all in the FIRST oppool pass. So floatcast is mainloop-INDEPENDENT and LaneDivide-reactivation-INDEPENDENT (RuleSplitFlow fires on any SUBPIECE-of-PIECE-through-join, no `Spec.laned` needed). This falsifies task#6 S3b's "reactivate LaneDivide for floatcast +0.038" (that was OLD-master + it's the wrong mechanism). LaneDivide stays INERT; floatcast is now task #17 = the SplitFlow port. **S1 (SplitFlow + RuleSplitFlow port on transform.rs) LANDED master `d171301`** byte-identical; S2 wire (RulePiece2Zext@5614 + RuleSplitFlow@5623) MEASURED floatcast 0.776→0.845 (+0.069, zero regress), gated. Residual (0.845 not ~0.95) = the straight-line return chain [[task8-mainloop-repeat]].
