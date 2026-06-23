# TODO — faithful port of Ghidra's decompiler to Rust

**The plan: [`docs/port-plan.md`](docs/port-plan.md).** How to work: [`AGENT.md`](AGENT.md).
Per-feature notes/gotchas: `.claude/memory/mosura-project.md`.

## Direction (read this first)

The objective is to **translate Ghidra's decompiler (C++ → Rust)**, validated against
Ghidra's **intermediate IR, exactly, stage by stage** — not to maximize a final-C
similarity score. The prior similarity-score chase rewarded approximations and punished
faithfulness, and the approximations don't compose. We are re-founding the decompiler
core on Ghidra's actual data model + `Action`/`Rule` pipeline. See `port-plan.md` §0–§3
for the full rationale and architecture.

## Status

- **SLEIGH engine:** done — bytes → instructions + raw p-code, **254/254 disasm/p-code
  parity** (6 arches). Keep. Never regress.
- **Decompiler prototype** (`src/decomp/`): an approximation. Corpus **0.756 avg
  structural similarity, 51/62 x86-64 datatests decompiled, 34 ≥ 0.70**. This is now a
  **coarse secondary gauge**, kept running while the faithful pipeline is built; **not a
  gate** (the `datatest_score` ratchet must never again block a faithful change).
- **Faithful pipeline** (`src/decompile/`, new): not started — P0 below.

## Phases (faithful port — detail in `port-plan.md` §4)

- [x] **P0 — Foundation** — done (data model, lifter→Funcdata load, Action/Rule
      framework, per-phase IR oracle, and the IR-parity gate are in place and tested)
  - [x] `oracle/capture --ir [action]` dumps Ghidra's per-phase IR (`Funcdata::printRaw`)
        by breaking at a named action — verified pre-heritage (raw p-code) and post-heritage
        (SSA + MULTIEQUAL, e.g. `EDI * #0x3`).
  - [x] `Varnode`/`PcodeOp`/`BlockBasic`/`Funcdata` **graph** data model — **core done**
        in `src/decompile/` (`opcode`/`space`/`varnode`/`op`/`block`/`funcdata`): the
        arena+index Varnode graph with Ghidra's flag set, `OpCode` (CPUI_*), `SpaceManager`,
        create/wire methods, `print_raw`. `BlockBasic` is a stub (CFG built in P1/P7).
  - [x] Build a `Funcdata` from the SLEIGH lifter's raw p-code (`build.rs::raw_funcdata`)
        — produces faithful Ghidra-shaped raw p-code (`output = OPCODE inputs`); graph
        consistency tested on real functions.
  - [x] `Action`/`Rule` framework skeleton (`action.rs`): `Action`/`ActionGroup`
        (+restart=`ActionRestartGroup` fixpoint), `Rule`/`ActionPool` (opcode dispatch to
        fixpoint), `ActionStart`. Fixpoint loop + rule dispatch tested.
  - [x] `tests/ir_parity.rs` — the gate plumbing; passes a structural check (mosura's
        loaded Funcdata covers exactly Ghidra's pre-heritage instruction addresses). Grows
        a normalized post-heritage op-graph diff in P1.
- [~] **P1 — Heritage** (`heritage.cc`) — in progress
  - [~] **CFG construction** (`cfg.rs::build_cfg`): leaders/edges + reachability prune;
        calls do NOT split blocks (per Ghidra). Block ranges match Ghidra exactly for the
        flow-aligned functions (x86_64_sem, elseif, twodim, threedim).
  - [x] **Flow-following decode** (`build.rs::raw_funcdata_flow`): worklist from the entry
        following fall-through + branch targets (calls fall through; indirect targets are
        P7). Faithful `followFlow`. NOTE the residual condconst/boolless/ifswitch CFG
        divergences are NOT flow drift — they are a lifter jump-target discrepancy
        (condconst) and unresolved jump tables (ifswitch, P7), tracked separately.
  - [x] Dominator tree + dominance frontiers (`dominator.rs`, Cooper).
  - [x] **Heritage SSA** (`heritage.rs`): semi-pruned Cytron — global-location detection,
        MULTIEQUAL placement at dominance frontiers, dominator-tree renaming. Produces
        valid SSA (reads linked, single-assignment, phi arity = #preds) for the aligned
        functions; matches Ghidra's def-use structure (verified on x86_64_sem).
  - [ ] Setup guards (e.g. synthetic `DF=0` at entry; call/store INDIRECTs, input guards).
  - [~] Refinement: `normalizeReadSize` **done** (`heritage.rs`, read side) — a
        sub-register read of a wider-written location becomes `SUBPIECE(W,0)`; closes the
        clean overlap gap (twodim/threedim fully, elseif reduced), SSA invariants hold.
        REMAINING: write side (`normalizeWriteSize`/PIECE for partial writes, AH-type
        offset+1), cross-offset CONCAT.
- [x] **P2 — Rule pool** (`ActionPool` + `ruleaction.cc` rules) — CORE DONE
      (framework + 6 foundational rules + pipeline; long rule tail is incremental)
  - [x] Op-rewrite primitives (`funcdata.rs`): `op_set_opcode`, `op_remove_input`,
        `total_replace`, `mark_dead`.
  - [x] Constant folding (`rules.rs::RuleConstFold` + `eval_const`, mirroring emu's
        parity-validated semantics) + `RuleTrivialArith` (`x OP x` identities). Unit-tested
        + integration: folds to fixpoint on real functions.
  - [x] `RuleTermOrder` (constant → slot 1), `RuleIdentityEl` (x+0/x*1/x*0),
        `RuleTrivialShift` (x<<0, shift≥width→0). Unit-tested + in the integration pool.
  - [x] Pipeline assembled (`pipeline.rs`): `ActionHeritage` → `default_rule_pool`;
        `pipeline::decompile(f)` runs end-to-end, tested.
  - [x] `RuleCollectTerms` (binary): a*c1+a*c2 → a*(c1+c2) (incl. a+a→a*2). Unit-tested
        (a+a*2→a*3); deeper trees collapse pairwise at fixpoint. Full N-ary gather remains.
  - [x] `RulePropagateCopy` (copy propagation): a read of `COPY(x)`'s output reads `x`
        directly → COPY dies. Unit-tested; closed ~10-25% of the op-count gap.
  - [ ] Incremental rule tail (Ghidra has 135 total): SUBPIECE pull-through
        (`RulePullsubMulti`/`RuleSubvarSubpiece`), `RuleSelectCse`, `RuleSub2Add`, the
        boolean/flag collapses, + ~85 others. Post-pipeline op count is now ~1.7-2x
        Ghidra's; the remaining gap is this tail.
- [x] **P3 — Dead code** (`deadcode.rs::ActionDeadCode`) — whole-varnode liveness seeded
      from side-effecting ops (returns/branches/stores/calls), propagated backward; removes
      the rule pool's collapsed ops + dead computations. Wired into the pipeline; invariant
      tested (no dead op survives; every kept op is a sink or its output is consumed/live-out).
      Mosura's live-op count is within ~2x of Ghidra's post-deadcode IR (the gap is the rule
      tail). INTERIM: seeds SysV return regs (RAX/XMM0) as live-out roots since the return
      value isn't wired to RETURN yet — replaced by P6 ActionReturnRecovery / addrtied.
- [ ] **P4 — Types** (`TypeFactory` + `ActionInferTypes`).
- [~] **P5 — Merge** (`merge.rs`+`cover.rs`) — variable grouping DONE
  - [x] `HighVariables` union-find + required marker merges (`Merge::mergeMarker`): a
        MULTIEQUAL/INDIRECT output is one variable with its inputs — threads SSA versions
        across control flow (loop counters etc.). Unit-tested + integration (phi versions
        merge, variable count drops on threedim/elseif/twodim).
  - [x] `Cover` (`cover.rs`): per-varnode liveness ranges, half-position model so a def
        doesn't interfere with the use it consumes (`x=x+1`); ground-truth unit-tested
        (disjoint↔no-intersect, overlap↔intersect).
  - [x] Same-storage merging (`merge_same_storage`): greedily union non-interfering
        HighVariables at the same storage → reused registers/slots become one variable.
        Validated: no two versions of one variable are simultaneously live; realistic
        counts (x86_64_sem 10 SSA→6 vars, twodim 36→13, threedim 57→21, elseif 196→25).
  - [ ] Variable NAMING (deferred to P8 PrintC / a NameVars action — the consumer).
- [ ] **P6 — Prototypes** (`FuncProto`/`ParamActive`/`AncestorRealistic` — call-arg/return).
- [~] **P7 — Structuring** (`structure.rs`) — core collapse done
  - [x] Structured `FlowBlock` graph + the reducible collapse rules (`ruleBlockCat`=list,
        `ruleBlockProperIf`, `ruleBlockIfElse`, `ruleBlockWhileDo`, `ruleBlockDoWhile`),
        ported from `CollapseStructure`. Unit-tested on each shape; fully structures
        reducible CFGs (x86_64_sem/twodim/threedim/boolless collapse to one block).
  - [ ] `ruleBlockOr` (short-circuit `&&`/`||`), `ruleBlockGoto` (irreducible → goto),
        `ruleBlockSwitch`, condition negation. (elseif/condconst stall pending these.)
- [~] **P8 — PrintC** (`printc.rs`) — emits real structured C
  - [x] Expression rendering (precedence-aware parens, signed constants), variable naming
        (params by SysV reg, HighVariable names), explicit/implicit (single-use inlining),
        function signature, return-value inlining, linear block emission. **Produces C
        whose body exactly matches Ghidra on straight-line functions** (x86_64_sem:
        `return param_1 * 3 + -5 + (param_2 >> 2);`, modulo type names).
  - [x] Structured control-flow emission: walk the `structure.rs` tree → `if`/`else`/
        `while`/`do-while`, condition from the CBRANCH (negated per the branch). threedim
        emits a `while` loop; well-nested.
  - [ ] Bigger gaps to Ghidra quality (NOT structuring): **stack-variable recovery** (the
        raw RSP/RBP frame ops aren't abstracted to locals — the largest gap), flag-condition
        simplification (RuleSborrow etc. — the rule tail), casts, P4 types, P6 return/params,
        gotos for irreducible CFGs.

Gate at every phase: mosura's IR matches Ghidra's IR on the datatests before moving on.
Retire the corresponding prototype code as each phase lands.

## Prototype findings worth carrying forward (from the approximation era)

These were the *symptoms* that motivate the faithful port; all are subsumed by P1–P6.
Detailed grounding (Ghidra source refs + why each approximation was net-negative) is in
`.claude/memory/mosura-project.md`.

- **Varnode overlap** (EAX/RAX, XMM 4-vs-8, 64-bit DIV `EDX:EAX`) → **P1 Heritage
  refinement** (`normalizeReadSize`/`WriteSize`). The XMM-only `loc_key` hack and the
  net-negative global-canonical attempt are both retired by faithful heritage.
- **CONCAT struct-packing** (piecestruct/concatsplit) → also **P1 refinement** (a wide
  read of adjacent narrow writes is assembled via PIECE; there are no PIECE ops in the
  raw p-code — heritage reconstructs them).
- **`phi_N` leaks** (nan/elseif) → **P1** (the `Live` args are heritage artifacts of the
  approximate SSA) + **P5 Merge** (surviving MULTIEQUALs become named HighVariables).
- **Call-arg over-counting** (indproto/deindirect2/piecestruct) → **P6** (`ParamActive` +
  `AncestorRealistic` + `forceInactiveChain`).
- **Types / array indexing / casts** (`*(p+8)` vs `p[1]`) → **P4 Types**.
- **Switch / division / floats** — the prototype's `jumptable`/`divrecover`/float handling
  are real Ghidra-grounded ports (`jumptable.cc`, `RuleDivOpt`, `FLOAT_*`); fold them into
  the faithful pipeline as the corresponding rules/actions (P2/P7) rather than re-deriving.

## Superseded docs (history)

`decompiler-plan.md`, `floats-plan.md`, `switches-plan.md`, `type-system-plan.md` describe
the approximation-era feature work. Kept for reference; the live plan is `port-plan.md`.
