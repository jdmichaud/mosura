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
- **Decompiler prototype** (`src/decomp/`): **removed** — a similarity-chasing
  approximation that didn't compose, fully superseded by the faithful pipeline. Its
  `datatest_score` gauge is retired; the `ccompare` structural comparator it carried was
  lifted to `src/ccompare.rs`.
- **Faithful pipeline** (`src/decompile/`): the decompiler. Corpus **0.8649 avg structural
  similarity, 54/60 x86-64 datatests ≥ 0.70** (`decompile_corpus`) — a diagnostic, NOT the
  target (see "Direction"). HEAD `9111b49`, 178 tests green.

  **Recent faithful subsystems landed** (this era; detail in `.claude/memory/`, handoff in
  `MEMORY.md` + `direction-faithful-port.md`): uniform `guard()` write+read normalization
  (heritage) → orcompare; `getNZMask`/`ActionNonzeroMask` (forward non-zero-mask analysis,
  42 rule sites); **Ghidra ActionPool per-op rule priority** (perop[opcode] + restart-on-
  opcode-change + SeqNum op order — mosura's flat pool was an unfaithful approximation);
  the **mosura↔Ghidra rule-application trace-diff tool** (`scripts/trace-diff.sh` +
  `oracle/capture_trace`, gated on `MOSURA_TRACE`/CPUI_DEBUG-OPACTION_DEBUG) — proves which
  Ghidra rules mosura fires/misses instead of guessing from IR; ~16 ruleaction.cc rules
  ported (many corpus-neutral IR-fidelity, unexercised ones unit-tested).

  **KEY PRINCIPLE** (`port-all-faithful-rules`): port EVERY faithful Ghidra rule; never
  "decline" one for being corpus-neutral. Unexercised ports get a synthetic-op-graph unit
  test, not a decline. The only legit "not yet" is a rule BLOCKED on a missing subsystem.

  **In flight:** Task #9 — port `SubVariableFlow` (`subflow.cc`), the worklist data-flow
  transform that dissolves byte-packing into narrow PIECE/CONCAT/zext. Unblocks 3 held rules
  (SubZext, Piece2Zext, AndDistribute). **Stage 0 (bit-level `consume` analysis, the backward
  dual of nzmask) LANDED byte-neutral (`9111b49`)**; Stage 1 (SubvariableFlow core structs)
  in progress. Plan: `.claude/memory/task9-subvariableflow-plan.md`. 5 held rules await their
  measured blockers: SubZext/Piece2Zext→#9, AndDistribute→#9(+#10 nzmask-freshness),
  AndCompare→#8 (sub2add-in-mainloop), NotDistribute→#4 (nan flag-simplification).

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
- [~] **P4 — Types** (`types.rs`+`infertypes.rs`) — foundation done
  - [x] `Datatype` lattice + metatype-ordered `meet` (Ghidra `TypeFactory`); `infertypes`
        assigns each varnode a local type from its def/uses (float/bool/pointer/int) and
        meets them per HighVariable. Wired into PrintC signature + return types.
  - [ ] Variable DECLARATIONS (faithful but currently exposes the variable-count gap —
        twodim emits 12 decls vs Ghidra's 1; ENABLE after CSE/global-var recovery brings
        the count down). Then CASTS (ZEXT/SEXT/SUBPIECE → `(T)x`), pointer pointees,
        struct/array types, param-size from P6.
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
  - [x] **Stack-variable recovery** (`stackvars.rs`): forward symbolic stack-pointer flow
        (Ghidra's `ActionStackPtrFlow`/spacebase) — `*(RSP/RBP+c)` → `stack[c]`, heritaged
        like registers, so spilled params link and the frame collapses (twodim 47→31 live
        ops; params flow directly, matching Ghidra's structure). RSP/RBP unified via entry-RSP.
  - [x] **P6 return recovery (faithful)** (`recover.rs`): port of `ActionReturnRecovery` +
        the core of `AncestorRealistic`. Wire RAX/XMM0 candidates to each RETURN pre-heritage;
        post-heritage keep only the candidate whose value traces to a REAL write (`is_realistic`)
        — distinguishes int(RAX)/float(XMM0)/void correctly. Replaces the deadcode seed-all
        crutch. Unit-tested (float/int/void/multiret). + global persistence (ram writes are
        kept side effects). Corpus 11→16 funcs ≥0.70; twodim .555→.717, threedim →.694,
        floatprint faithful .789.
  - [x] **Shift-add strength reduction** (`as_term` ⊇ `INT_LEFT`, Ghidra `getMultCoeff`):
        `(x<<2)+x → x*5`; cascades to drop the redundant global copies. twodim .717→.829,
        threedim →.738, nestedoffset →.950. Unit-tested.
  - [x] **RuleSborrow** (faithful port): `sborrow(V,W) != ((V-W) s< 0) => V s< W` (+ `==`/
        swapped/`sborrow(V,0)=>false` variants). Collapses the x86 signed-compare flag idiom
        to a clean signed comparison on every if/loop. Unit-tested. forloop1 condition now
        `uVar1 < param_1` (matches Ghidra). Gauge ~flat (coincidental flag tokens lost).
  - [x] **Call-argument recovery** (`recover_call_args`/`resolve_call_args`): symmetric to
        return recovery — wire RDI..R9 candidates to each CALL pre-heritage, post-heritage keep
        the contiguous `is_realistic` prefix (AncestorRealistic). + `func_0x<addr>(...)` naming,
        + param detection counts only USED param-register inputs (drops the wired scratch).
        Unit-tested. good 18→21, avg →0.5567. forloop1 `func_0x00400430(0x400820)` matches.
        LIMIT: pure param-passthrough args (forwarded untouched, unwritten) not yet recovered
        (needs directWrite / fuller ParamActive); float (XMM) args are a follow-up.
  - [x] **Loop-increment emission**: a value whose sole use feeds a MULTIEQUAL is now
        explicit (materialized as the merged-variable assignment), so loop bodies emit
        `uVar1 = uVar1 + 1`. forloop1 body matches Ghidra; good 21→24, avg →0.5737.
  - [x] **For-loop recognition** (`findLoopVariable`/`findInitializer` port): trace the
        condition var to the loop-header phi; its body-defined input is the iterator (moved to
        the `for` update), its pre-loop input the initializer. Emits `for (init; cond; iter)`,
        iterator/init suppressed in their blocks. + phi outputs always named (no raw
        `MULTIEQUAL(...)`). forloop1 .703→.865, forloop_varused →.836, threedim →.791; good →26.
        + for-loop INIT now recovered: a targeted heritage fix links a sub-register phi
        input (`EBX`) to its wider covering reaching def (`RBX` initializer) via SUBPIECE, so
        the `i=0` initializer survives; for_parts carries the init varnode (often a folded
        constant). forloop1 →.950, forloop_varused →.886; good →28. Safe (only fires when the
        exact-width def is absent — in-block def chains untouched; no corpus regressions).
  - [x] **`jle`/`jbe` flag idiom** → `<=` (faithful chain): fixed RuleSborrow's constant
        comparison (constants aren't interned — compare by value via `same_value`), + ported
        RuleEqual2Zero (`(a-b)==0 → a==b`) and RuleLessEqual (`V<W || V==W → V<=W`). threedim
        condition `uVar1 <= 0x1d`; good →30. Unit-tested.
  - [~] **Short-circuit `&&`/`||` structuring** (Ghidra COND_AND/COND_OR): `rule_short_circuit`
        merges two chained condition blocks (a's true→b + shared false ⇒ `a && b`; a's false→b
        + shared true ⇒ `a || b`) into a two-out condition block; render_condition joins them
        `(a) && (b)`. Unit-tested; fires on elseif/loopcomment/nan, renders correctly. CORPUS-
        NEUTRAL for now — those functions are dominated by OTHER gaps (branchless-flag `||`,
        float-compare simplification, irreducible CFG). A correct foundation that pays off once
        those are fixed.
  - [ ] DOMINANT gaps blocking the &&/|| funcs: branchless boolean flags (orcompare's
        `(a)*2 | (b)<<7 != 0` → `a || b`), global-var naming
        (`xRam...`), float-compare/NAN simplification, irreducible-CFG gotos (elseif).
  - [x] **Print-time boolean negation** (`render_negated`): a false-edge condition pushes
        the negation into the expression instead of `!(...)` — `!(!x)` cancels to `x`, `==`/`!=`
        flip. condmulti cond `if (param_1 == 0)`; avg →0.5973, condmulti →.764, dupptr →.881.
  - [ ] Remaining quality: (`(x<<2)+x`→`x*5`), global-var recovery, flag
        conditions (RuleSborrow + rule tail), casts, P4 types, P6 return/params, gotos. THEN
        whole-corpus measurement vs Ghidra `--c` is meaningful.

Gate at every phase: mosura's IR matches Ghidra's IR on the datatests before moving on.
Retire the corresponding prototype code as each phase lands.

## Analysis port (second track — `docs/analysis-port-plan.md`)

A **separate, largely orthogonal** subsystem: a faithful port of Ghidra's **auto-analysis**
(the Java side that takes a binary *file* and decides *what to decompile* — loaders,
function discovery, references, switch/param recovery). Distinct from the decompiler port
above (which works on one already-located function). Reference source is Ghidra's Java tree
(`Features/Base/.../app/plugin/core/analysis`, `Framework/SoftwareModeling/.../program`),
not `decompile/cpp`. Oracle is `analyzeHeadless` Program-state snapshots, not `decomp_dbg`
per-action IR. New module tree `src/analysis/`. **Not started.**

- **A1–A5 are independent of the decompiler port; A6 gates on it.** Don't sequence A1–A5
  behind the P-phases.

- [x] **A0 — Oracle + corpus** — done (analyzeHeadless oracle + harness; reproducible).
  - [x] Real-binary corpus (`oracle/analysis-corpus/`): `freestanding.elf` (-nostdlib, clean)
        + `basic.elf` (dynamic, realistic), built by `build.sh`, committed (toolchain-stable).
  - [x] Snapshot schema (`src/analysis/snapshot.rs`): canonical, line-oriented, diff-friendly
        v1 = loaded memory map (`block`) + recovered functions (`func`); lenient parser +
        `render` round-trip; the contract mosura emits in A1–A4. Wired `src/analysis/`.
  - [x] **analyzeHeadless oracle** — `scripts/build-ghidra-dist.sh` builds a runnable Ghidra
        dist from the clone (the bare clone refuses; handles two env gotchas — UTF-8 locale +
        oracle-binary `ip` pollution); `oracle/ghidra_scripts/DumpAnalysisSnapshot.java` is the
        `-postScript` dumper; `scripts/capture-analysis.sh` regenerates all goldens offline.
        Full chain in `oracle/analysis-capture.md`.
  - [x] Committed goldens (`goldens/analysis/{freestanding,basic}.snapshot`) from analyzeHeadless
        (Ghidra 12.0.3). Cross-checked **identical** to a GhidraMCP capture of the same build.
  - [x] `tests/analysis_parity.rs` red-baseline ratchet (`EXPECTED_ANALYSIS_PASS=0`, 0/2 today)
        + `analysis::analyze_binary` (Unimplemented).
  - [ ] (carry to A4/A5) Snapshot v2 sections: `entrypoint` / `sym` / `data` / `ref` + function
        body ranges; per-analyzer staging via a capture `-preScript`.
- [x] **A1 — Program model** (`src/analysis/program/`) — the shared mutable DB every analyzer
      reads/writes, reusing the decompiler's `Address`/`SpaceManager`. Done:
  - [x] `AddressSet`/`AddressRange` (`address_set.rs`) — inclusive coalesced ranges + the full
        algebra (`union`/`intersect`/`subtract`/`xor`/`contains`/`num_addresses`), method names
        mirroring `AddressSetView`; thorough unit tests incl. adjacency + `u64::MAX` boundary.
  - [x] `Memory`/`MemoryBlock` (`memory.rs`) — named blocks, perms, initialized bytes, byte reads.
  - [x] `SymbolTable`/`Symbol` (`symbol.rs`), `FunctionManager`/`Function` (`function.rs`).
  - [x] `Listing`/`CodeUnit` (`listing.rs`) — container + types; **populated by A4**.
  - [x] `Program` aggregate + `Program::snapshot()` projection to the v1 oracle format; tied to
        the A0 golden (`snapshot_projection_matches_freestanding_golden_body` reproduces
        freestanding's body from a hand-built Program).
  - [ ] `ReferenceManager`/`Reference` — deferred to **A5** (references come with `SymbolicPropogator`).
- [~] **A2 — loaders** (`src/analysis/loader/`) — memory maps done for ELF + PE; MZ + symbols pending.
      Containers parsed with the `object` crate; only Ghidra's **block-layout output** is ported.
      Gate is the **loader-stage** golden (`<name>.loaded.snapshot`, `-noanalysis`) — the loader's own
      output, before analysis adds artificial blocks (e.g. PE `tdb` = ThreadEnvironmentBlock).
  - [x] **ELF** (`elf.rs`): allocated sections → named blocks; `PT_LOAD` leftovers → `segment_<phdr>.<n>`
        (via `AddressSet::subtract`) with `isDiscardableFillerSegment` pruning (≤0xff & all-zero);
        `EXTERNAL` block (undefined dynsyms, page-aligned after image).
  - [x] **PE** (`pe.rs`): `Headers` block (Ghidra `getVirtualSize`) + section blocks sized
        `max(VirtualSize, SizeOfRawData)`, gaps unfilled. `tdb` is analyzer-made, not loader.
  - [x] **MZ** (`mz.rs`, 16-bit DOS): segments discovered from relocation fixups (`+0x1000`) + the
        initial/entry segments → `CODE_<i>` blocks to the next segment, `CODE_<i>u` uninit tail,
        `DATA` (`e_minalloc` paragraphs). Flat-linear addresses (`seg<<4`), `x86:LE:16:Real Mode`.
        Header + relocations hand-parsed (`object` doesn't decode bare MZ). WAR2.EXE/comcom32 match.
  - [x] Magic dispatch (`loader::load`: ELF / MZ→PE / MZ→DOS). **Memory-map parity 5/5**
        (freestanding, basic, cnv PE, comcom32 MZ, WAR2 MZ). PE/MZ binaries are user-provided
        (not committed) → harness skips if absent; loader-stage goldens committed.
  - [ ] **LE (Linear Executable) — DEFERRED until Ghidra parity** (beyond-Ghidra; no oracle).
        WAR2.EXE is a DOS/4GW-bound LE; Ghidra (no LE loader) sees only the 16-bit MZ stub, which
        mosura now matches. When parity is reached, build a **native `le.rs`** (NOT the ELF32-wrapper
        workaround), validated against the `warcraft2-re` object ground truth + the LE spec. Full
        design + WAR2 specifics: [`docs/le-loader-notes.md`](docs/le-loader-notes.md).
  - [x] **Symbols + entry points** → `SymbolTable`/`entry_points` (snapshot **v2** `sym`/`entry`;
        validated against the loader-stage golden). Snapshot-v2 schema + `DumpAnalysisSnapshot`
        dumper + `loader_detail_parity` gate. **Loader detail 5/5** (funcs+entries+symbols exact)
        across all formats:
    - [x] **ELF**: `.symtab` (STT_FUNC→Function else Label; globals+`e_entry`→entries); dynamic
          extras — `.dynsym` imports → EXTERNAL-block slots, `__DT_*` labels from `.dynamic`,
          init/fini/preinit-array targets → entries, `_DYNAMIC`, idempotent `createSymbol` dedup.
          freestanding + basic both exact.
    - [x] **PE** (`recover_pe`): `.pdata` RUNTIME_FUNCTION → `FUN_<addr>` functions (skipping
          chained-unwind), `AddressOfEntryPoint` → `entry`, `_tls_index` from the TLS directory.
          cnv exact (1767 funcs).
    - [x] **MZ** (`MzLoader.processEntryPoint`): `entry` label at `CS:IP` + entry point. WAR2/comcom32 exact.
  - [ ] Relocations; non-x86-64 language ids; stripped-dynsym defined symbols (only `.symtab`
        defined symbols are processed today — fine for the corpus).
  - [ ] **Loader-stage references** (audit finding): Ghidra's `-noanalysis` loader marks up ELF
        header/dynamic structures and emits DATA refs (e.g. `e_entry` field → `_start`) — 4 on
        freestanding, 36 on basic. mosura's loader emits none; not covered by `loader_detail_parity`
        (which compares blocks/funcs/entries/symbols, not refs). Needs ELF data-structure markup.
  - [ ] Generalize language-id mapping beyond x86-64 (16/32-bit, other arches).
- [x] **A3 — Framework** (`priority.rs`/`analyzer.rs`/`manager.rs`). `AnalysisPriority`
      ladder; `Analyzer` trait + `AnalyzerType`; `AutoAnalysisManager`+`Scheduling` — per-
      analyzer `AddressSet` accumulators, fact-routing notifiers (`code_defined`/
      `function_defined`/…), fixpoint run loop. Analyzers notify `Scheduling` directly
      (explicit-channel model). Unit-tested: priority order + re-trigger to fixpoint.
- [x] **A4 — Disassembly + function discovery** (`analyzers/`) — engine + converged gates landed.
  - [x] `Disassembler`: SLEIGH-driven recursive descent (fall-through + branch targets;
        `followFlow`) → `Listing` code units; static call targets → new functions.
  - [x] `FunctionCreator`: function at each executable seed (Ghidra `createEntryFunction`
        `isExecute` check — no data-address functions); idempotent; schedules disassembly.
  - [x] `analyze(program)` seeds from loader functions+entries, runs to fixpoint.
  - [x] **Converged gates** (snapshot `insn` section): `disassembly_parity` — code units a HARD
        subset of Ghidra's (0 misaligned decodes), recall 142/146; `function_parity` — no spurious
        functions, recall 17/19. (audit fix: A4's core output had been ungated.)
  - [ ] **Function bodies**: `FunctionManager` functions carry an empty `AddressSet` body; Ghidra
        computes the body. Not snapshot-gated; needed by A6 (decompiling a function).
  - [ ] The 4 instructions / 2 functions mosura misses (PLT[0] `0x401020`, GOT-indirect `0x405010`)
        need PLT-stub disassembly / pointer-following. Indirect branches (jump tables) are A6.
- [x] **A5 — References + `SymbolicPropogator`** — reference model, flow refs, propagator,
      and the ref-parity oracle landed. **reference parity 29/37, 0 false positives** (mosura
      never invents a reference Ghidra lacks); residual recall is A6 / deeper propagation.
  - [x] **ReferenceManager** (`program/reference.rs`): `Reference`/`RefType` (DATA/READ/WRITE +
        flow kinds, Ghidra names); idempotent add + from/to queries; wired into `Program`.
  - [x] **Flow references** in the `Disassembler`: call → UNCONDITIONAL_CALL, branch →
        UN/CONDITIONAL_JUMP; self-target (`hlt` = `BRANCH <self>`) suppressed.
  - [x] **`SymbolicPropogator`** (`analysis/symbolic.rs`): `SymValue` lattice + `VarnodeContext`;
        `flow_constants` path-sensitive walk; `makeReference` gated on `memory.contains`. `ram`
        operand → READ/WRITE; `const`-as-address → DATA (any data op, not STORE); LOAD/STORE pointer
        resolved via register propagation; constant-folds INT_ADD/SUB/AND/OR/ZEXT/SEXT. Flow-op
        operands excluded (they are flow edges, not data). `ConstantPropagationAnalyzer` drives it.
  - [x] **Snapshot v3** `ref` section (`DumpAnalysisSnapshot` + `snapshot.rs` + `Program.snapshot`);
        `reference_parity` gate — HARD no-false-positive subset assert + recall ratchet (≥29).
  - [ ] *Recall residual (A6 / future, not A5):* COMPUTED_CALL / INDIRECTION / PARAM (indirect-call +
        parameter analysis), PLT-stub disassembly, GOT pointer-following (memory-content reads),
        register-relative (stack) values, context merge at joins.
  - [ ] *Faithfulness note (unobservable on the corpus):* Ghidra uses two ref-address thresholds —
        `minStoreLoadRefAddress`=4 (known/direct) and `minSpeculativeRefAddress`=1024 (speculative
        constants). mosura uses 4 for resolved load/store and bypasses for literal operands; all
        corpus addresses are ≫1024 so results are identical, but the speculative threshold isn't modeled.
- [ ] **A6 — Decompiler-driven analyzers.** Switch recovery + parameter-ID via the
      decompiler (plan §2c); retire `decomp/jumptable.rs`; gate on jump-table + param
      parity. **Depends on the decompiler port.**
- [ ] **A7 — The tail.** Non-returning functions, shared-return, stack/purge, demanglers,
      strings/data, arch-specific propagation; each gated on Program-state parity.

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
the approximation-era feature work on the now-removed `src/decomp/` prototype. Kept for reference; the live plan is `port-plan.md`.
