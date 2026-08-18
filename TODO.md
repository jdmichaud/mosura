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
  - [x] **Loader-stage references** (audit finding) — ELF data-structure markup DONE.
        `loader_reference_parity` gate: freestanding **4/4 exact**, basic **32/36**, 0 spurious
        (ratchet 36). Implemented:
    - [x] **ELF header + program-header markup** (`markup_elf_structures`): `e_entry`→entry,
          `e_phoff`→phdr table, each loaded segment's `p_vaddr`→load address (Ghidra
          `markupElfHeader`/`markupProgramHeaders`; skips PT_NULL + offset-0 LOAD).
    - [x] **Dynamic-table field refs** (`markup_dynamic`): each address-valued `DT_*` `d_un` → target.
    - [x] **`.init_array`/`.fini_array`** slot → function pointer; **DT_PLTGOT[0]** → `_DYNAMIC`.
    - [x] **Relocations** (`apply_external_relocations`, `R_X86_64_GLOB_DAT`/`JUMP_SLOT`): GOT/PLT
          slot → EXTERNAL slot DATA refs + patched bytes (`Memory::write_u64`). basic 3/3 exact.
    - [ ] **PLT disassembly + `INDIRECTION`** (remaining 4 basic refs): the loader disassembles
          `.plt` and types `jmp *[GOT]` as INDIRECTION — an **indirect-flow** concept best done
          faithfully in **A6** (not hacked into the loader). Addend-only relocs (`R_X86_64_RELATIVE`)
          likewise when those binaries appear.
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
  - [x] **Converged gates** (snapshot `insn`/`fnbody` sections): `disassembly_parity` — code units a
        HARD subset of Ghidra's (0 misaligned), recall 142/146; `function_parity` — no spurious
        functions, recall 17/19; `function_body_parity` — bodies match Ghidra **exactly** (17 validated).
        (audit fix: A4's core output had been ungated.)
  - [x] **PE/MZ convergence** (`pe_mz_convergence_parity` + `pe_robustness_cnv`): comcom32 exact
        (0 spurious, 0 misaligned); war2 bounded (0 spurious, ≤8 misaligned); cnv smoke (opt-in).
  - [x] **Perf** (audit/perf pass): fixed O(N²) blowups — `Listing` sorted-Vec→HashMap (the big one),
        `Reference`/`Symbol`/`FunctionManager` per-add sort→HashSet, `SymbolicPropogator` String-key→int
        + `flow_constants` bounded to function entries. cnv analyze 1043s→142s. Also fixed a real SLEIGH
        engine panic (`fmt_hex(i64::MIN)` negate-overflow) that crashed PE/MZ disassembly.
  - [x] **Call-target functions** (audit fix): create a function at every in-memory direct-call
        target (not just executable) — Ghidra's behaviour; comcom32 3/8 → 8/8 exact.
  - [ ] **war2/cnv precision** (later-phase, A6/A7 — audit-verified, not bugs): over-decode vs
        Ghidra's data analysis. **Audit-and-fix loop conclusion:** every remaining miss across the
        corpus is A6 (indirect flow: basic PLT-via-GOT, war2 142 unreached) or A7 (data analysis:
        cnv 2 spurious funcs + 1097 misaligned — their callers are over-decoded non-Ghidra
        instructions) or war2-16-bit specifics (12 jump-target/boundary funcs). No fixable-without-
        A6/A7 bug remains in the corpus.
  - [x] **Function bodies** computed (see `function_body_parity`); exact match. (was: empty body gap)
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
- [~] **A6 — Decompiler-driven analyzers** (the tracks converged — merged master's
      decompiler in; `analysis/decompiler.rs` bridges Program → `Funcdata`).
  - [x] **Bridge** `decompile_function(program, entry)`: build a `Funcdata` from the Program's
        memory blocks + run the pipeline, exposing `jump_tables()`/`func_proto()`.
  - [x] **DecompilerSwitchAnalyzer** (`analyzers/switch.rs`): decompiles functions with an
        unresolved indirect branch (tracked in `Program.indirect_branches`), emits COMPUTED_JUMP
        refs from each BRANCHIND to the recovered case targets + schedules them as code. Gated:
        `switchtab` COMPUTED_JUMP edges match Ghidra exactly (7/7, 0 spurious).
  - [x] **Parameter-ID → PARAM** (`symbolic.rs` `add_param_references`): NOT decompiler-driven —
        a port of `SymbolicPropogator.addParamReferences`/`createVariableStorageReference`/
        `makeVariableStorageReference` (the ConstantPropagationAnalyzer's parameter analysis,
        `checkParamRefs=true`/`checkPointerParamRefs=false` on x86-64). On a CALL/CALLIND, each
        integer argument register holding a constant mapped address emits a PARAM **from the
        instruction that last set it** (`getLastSetLocation` → `VarnodeContext.lastSet`). The arg
        registers are resolved from the default convention's `ParamList` (`integer_arg_registers`
        → `fspec::sysv_input`, the same model the decompiler uses) — Ghidra's
        `getDefaultCallingConvention` + `getArgLocation`, **not a hardcoded list**. basic:
        `0x401054→0x401168`, `0x401194→0x402004`, with the speculative DATA dropped (Ghidra
        `ScalarOperandAnalyzer` skips an already-referenced operand). The convention *selection*
        still gates on the compiler spec (only System V / gcc is modeled until the cspec track
        lands — see below); PE/MZ get no SysV registers, so 0 false positives.
  - [x] **Indirect calls → COMPUTED_CALL**: the SymbolicPropogator resolves a CALLIND whose
        target is a constant (`call *[GOT]`, slot relocated to the external in A5) → COMPUTED_CALL.
        basic's 2 COMPUTED_CALL recovered, matching Ghidra; code-ref recall 29→31, 0 false positives.
  - [x] **INDIRECTION** (code-based): faithful port of Ghidra
        `SleighInstructionPrototype.getDynamicOperandRefType` — a BRANCHIND/CALLIND/RETURN whose
        flow target is the operand's static `ram` address (a PLT stub's `jmp *[GOT]`) gets an
        INDIRECTION ref to that slot, created at disassembly time. basic's PLT `jmp *[GOT]`
        recovered, recall 31→32, 0 false positives.
  - [x] **Flow-type classification + COMPUTED_CALL_TERMINATOR** (`flowtype.rs`): port of
        `SleighInstructionPrototype.walkTemplates`/`flowListToFlowType`/`convertFlowFlags` +
        `FlowOverride.getModifiedFlowType`, derived from the lifted p-code. The SymbolicPropogator
        types a resolved BRANCHIND target with the instruction's flow type (COMPUTED_JUMP); a new
        `ExternalJumpAnalyzer` (port of `OperandReferenceAnalyzer.checkForExternalJump`) re-types a
        JUMP into the EXTERNAL block via the CALL_RETURN override → COMPUTED_CALL_TERMINATOR. basic
        `0x401030→0x405008 COMPUTED_CALL_TERMINATOR`.
  - [x] **PLT[0]'s INDIRECTION** via full `.plt` disassembly (`mod.rs` `plt_linear_sweep`): port of
        `ElfDefaultGotPltMarkup.processPLTSection`/`disassemble` — linearly sweep `.plt` from
        `start+16` so the lazy-resolve stubs decode. basic `0x401026→0x403ff8 INDIRECTION` +
        `0x40103b→0x401020`; disassembly 102→106/106, code-ref 31→ all A6 refs recovered.
  - [x] **Remaining basic code-ref misses** — resolved/identified by A7: the 6 `.eh_frame_hdr`
        INDIRECTION are recovered by Task 2; `0x401020→0x403ff0 READ` (in PLT[0]) by Task 1
        (SharedReturn makes PLT[0] a function). The single remaining code-ref miss is
        `0x401004→0x405010 DATA` (basic code-ref 32/33): INVESTIGATED — it is the **same deferred
        behavior** as the last missing function (`__gmon_start__@0x405010`). The loader emits the
        GOT relocation `0x403fe0→0x405010 DATA` + an external Label; mosura already recovers the
        GOT-slot READ (`0x401004→0x403fe0`) and the COMPUTED_CALL (`0x401010→0x405010`). What it
        does NOT yet do is (a) propagate a DATA ref from the pointer-loading instruction through
        the GOT slot to the slot's referent, and (b) promote that referent to a Function. Both are
        Ghidra constant/reference-propagation + function-creation-at-call/pointer-target —
        **A6-family indirect-flow follow-on, not an A7-tail analyzer**. Reported, not invented.
  - [~] **war2 switches/COMPUTED_CALL** (Task 4): honestly 0/20 COMPUTED_JUMP + 0/2 COMPUTED_CALL,
        0 spurious. war2 loads as x86:LE:16:Real Mode (DOS/4GW MZ stub); the switch sources are in
        protected-mode LE code the 16-bit function discovery never reaches, so they're never
        disassembled (a code-discovery gap, not a switch-analyzer failure). The pe_mz gate now locks
        the computed-flow subset invariant (0 spurious) for war2 + comcom32.
  - [x] *Decompiler-track gap reported + FIXED by master* (`4049e5d`, merged): gcc -O2
        register-guard switches now recover (cfg root at the entry, not the lowest-address block);
        switch fixture upgraded to the realistic -O2 form, A6 switch gate 7/7 through the bridge.
- [~] **A7 — The tail.** Self-contained analyzers gated on Program-state parity. Status:
  - [x] **Task 1 — SharedReturnAnalyzer** (`analyzers/shared_return.rs`, `48e79ed`): port of
        `SharedReturnAnalysisCmd` (jump-to-function-entry tail call → retype JUMP ref as
        UNCONDITIONAL_CALL via FlowOverride.CALL_RETURN; `assumeContiguousFunctions` creates a
        function at a boundary-crossing jump target). Recovers FUN_00401020 (PLT[0]); function
        parity 18/19, body parity +1, ref `0x40103b→0x401020` retyped, `0x401020→0x403ff0 READ`
        recovered. 0 FP.
  - [x] **Task 2 — GCC exception-frame analyzer** (`analyzers/eh_frame.rs`, `ef13673`): port of
        `EhFrameHeaderSection`+`FdeTable` (DWARF EH pointer-encoding decoder). The 6
        `.eh_frame_hdr` FDE-table INDIRECTION refs + the eh_frame_ptr/FDE DATA refs;
        eh_frame-reference parity 13/13, 0 spurious.
  - [x] **Task 3 — NoReturnFunctionAnalyzer** (`analyzers/noreturn.rs`, `276e0a2`): port of
        `NoReturnFunctionAnalyzer` with the ELF/PE name lists VERBATIM from Ghidra's data files;
        disassembler stops fall-through after a direct call to a flagged function
        (Disassembler.java:1288 isNoReturnCall → CALL_RETURN). FAITHFUL but **inert on the
        available corpus** (verified): basic/freestanding reach no listed function by a direct
        call; cnv surfaces no exit/abort symbol mosura matches (diagnostic: 0 flagged). The "No
        Return" flag is not in the snapshot schema; effect is only a subset-preserving reduction.
  - [N/A] **Task 4 — stack/purge.** NOT snapshot-validatable: Ghidra's StackVariableAnalyzer
        creates STACK-space references + stack variables that feed the DECOMPILER; the snapshot
        dump (DumpAnalysisSnapshot.java) filters stack/register/external/const-space refs out by
        design (grep confirms 0 STACK refs in every golden). Scoped out faithfully — no stack
        facts invented to match. (Stack-pointer flow itself is the decompiler track's
        ActionStackPtrFlow, TODO line 130.)
  - [x] **Task 5 — defined-data units** (`e394fd7`): snapshot `data` section added
        (snapshot.rs + DumpAnalysisSnapshot.java + Program::defined_data); all goldens
        re-captured (only `data` lines added, no fact drift). The GCC eh_frame analyzer defines
        the `eh_frame_hdr`/`dword`/`fde_table_entry` units faithfully (EhFrameHeaderSection/
        FdeTable createData). New `data_unit_parity` gate: basic 9/99, 0 spurious. Grounding note:
        Ghidra does NOT define the printf `"%d\n"` string (it stays undefined), so that A7-spec
        target does not exist. ELF-structure markup (Elf64_*) + `.eh_frame` CIE/FDE field markup
        are the deferred remainder (loader / EhFrameSection subsystems).
  - [ ] **Task 6 — demangler** (its own track; not a tail analyzer). Ghidra's GNU/Itanium
        demangler is NOT a Java grammar: `GnuDemangler` shells out (`GnuDemanglerNativeProcess`)
        to the bundled native `demangler_gnu_v2_41` binary (libiberty cp-demangle, binutils 2.41;
        source under `GPL/DemanglerGnu/src/`); the Java side only re-parses the native output.
        DECISION (wrap, don't port): wrap the pure-Rust **`cpp_demangle`** crate (the libiberty
        cp-demangle equivalent). Rationale — mosura is **Apache-2.0** and libiberty is **GPL**, so
        porting/static-linking it would force a relicense; mosura's build is pure-Rust (no C
        toolchain). `cpp_demangle` is Apache-2.0/MIT, pure Rust, and from gimli-rs (same org as the
        `object` crate already in the tree — its `demangle` feature wraps cpp_demangle, so possibly
        no new direct dep). Add a small C++ fixture + golden and **validate the demangled `sym`
        names against Ghidra**; cpp_demangle implements the ABI independently, so reconcile any
        formatting deltas against the golden (FFI-libiberty fallback is NOT acceptable — GPL vs
        Apache-2.0). Hand-rolling an Itanium grammar remains forbidden. (rustc-demangle /
        msvc-demangler cover the Rust / MSVC schemes when needed.)

## Compiler-spec (cspec) track — calling conventions from the `.cspec`, not hardcoded

A **cross-cutting** track shared by the decompiler and analysis ports. Today both fake the
calling convention: the decompiler's `fspec::sysv_input`/`sysv_output` build the System V
AMD64 `ParamList` in code, and the analysis param-ID selects it by gating on
`compiler_spec_id == "gcc"`. Ghidra instead loads the convention from the processor's
`.cspec` XML (e.g. `x86-64-gcc.cspec`, `x86-64-windows.cspec`). Porting that removes every
hardcoded convention and unlocks non-SysV targets (MS-x64 on the PE corpus, `thiscall`, ARM
AAPCS, …). Reference source: Ghidra `Framework/SoftwareModeling/.../program/model/lang/`
(`BasicCompilerSpec`, `PrototypeModel`, `ParamListStandard`) + the `.cspec` files under each
`Ghidra/Processors/<arch>/data/languages/`.

- [ ] **C0 — `.cspec` loader.** Locate + parse the language's `.cspec` (alongside the `.sla`
      already loaded by `lang::load`): the `<compiler_spec>` → `<default_proto>` and named
      `<prototype>` elements, each with `<input>`/`<output>` `<pentry>` resources (register
      and stack-param storage, type classes, alignment). Build `fspec::ParamList`/`ProtoModel`
      from the parsed pentries — **replacing** the hand-built `sysv_input`/`sysv_output`.
      (Coordinate with the decompiler track: `fspec.rs` is on `master`.)
- [ ] **C1 — `getDefaultCallingConvention` + `getArgLocation`/`assignMap`.** Port
      `CompilerSpec.getDefaultCallingConvention()` (the convention named by `<default_proto>`)
      and the forward arg→storage assignment `PrototypeModel.getArgLocation` →
      `ParamListStandard.assignMap`/`assignAddress` (the per-group `status[]` resource
      consumption — faithful, replacing the analysis track's GENERAL-register-walk
      approximation in `integer_arg_registers`).
- [ ] **C2 — wire both consumers onto it.** Decompiler `recover_func_proto` selects its
      `ParamList` via the loaded cspec instead of calling `sysv_input` directly; analysis
      param-ID drops the `gcc` gate and uses `getDefaultCallingConvention().getArgLocation(...)`
      for any convention. Then PE/MS-x64 (RCX/RDX/R8/R9) parameter analysis works — add a
      gated check that the PE corpus (comcom32/cnv) recovers its convention's PARAM refs as a
      clean subset of Ghidra.

## Debug-information track — `D0`–`D12` (`docs/debug-info-port-plan.md`)

**Not started.** Scope is **everything Ghidra reads**: DWARF (20,440 lines), PDB Universal
(671 files / 75,680 lines, but ~40k of distinct logic — 476 of those files are one-class-per-record
CodeView catalogues that port as enums, see the plan's §0a), PE CodeView + COFF debug (applied by
the **loader** `AbstractPeDebugLoader`, not an analyzer), separate `.dbg` files, Go symbol metadata, PEF debug,
MachO `.dSYM`, and external debug files (build-id / `.gnu_debuglink`). MSDIA is Windows-only by
construction — we port the refusal. Ghidra has no stabs support, so neither do we. mosura today
reads none of it (only DWARF *pointer encodings* in `analyzers/eh_frame.rs` and ELF
`SHT_SYMTAB`/`SHT_DYNSYM` names in `loader/elf.rs`).

Sequenced **spine-first**, not layer-first: `D0` is a thin vertical slice — minimum sink, minimum
DWARF, one `gcc -g` hello world named and locked and commented end to end — and `D1` immediately runs
a *second* format (PE CodeView) through the same substrate, because format-neutrality costs one
fixture to prove at `D1` and a refactor to discover at `D8`. Everything after that is breadth over a
working path. The format blocks are independent of each other; they share only the sink.

Two findings that shape the plan:

- **The parsers are the easy half — there is no sink.** No type registry, no function signature, no
  comment database, no source map, and no `inputlock`/`outputlock`/`typelock` on `FuncProto`, which
  is precisely how Ghidra lets declared info beat recovery. That is why the spine includes a lock and
  a comment from day one: without them a parser changes nothing an observer can see.
- **How debug info reaches decompiled output.** Not through source text (DWARF has none, and Ghidra
  reads no embedded source anywhere) and not through the line map (`SourceMapEntry` has **zero**
  references in `Features/Decompiler` — it feeds a listing field and a table). It reaches the C text
  through **code-unit comments** carrying `file:line`, which `printc.cc` prints from `commentdb`.
  Types/signatures/locals/CC change the code; comments change the text around it.

**Governing policy — port the judgement, offload the parsing.** What we want from Ghidra is the
analysis and the decompilation; reading a debug format is commodity work that goes to reliable Rust
crates as long as they provide what we need. Measured against Ghidra's source: **35,830 lines are
decisions we port** (DWARF importers + fixups 12,828, PDB applicator 21,156, PE debug loader 402, Go
1,327, PEF 117) and **67,136 are format reading we do not write** (`gimli` for DWARF's 7,612, the
`pdb` crate for PDB's 54,524 including the 326-record catalogue, and CodeView's 4,927) — **65%
offloaded**, which is what makes covering every format realistic instead of aspirational. Same line
`loader/elf.rs` already draws with `object`. The crate supplies bytes and structure; we supply every
judgement, including **every Ghidra refusal** (`gimli` reads split DWARF happily; Ghidra refuses it,
so the refusal is ours). Where a crate cannot express a Ghidra decision, the decision wins: decode
that one record locally, or contribute upstream — never fork, never bend the decision. The live risk
is PDB record coverage, so `D8`/`D9` carry an adoption gate (itemised coverage check, `unsafe`/fuzzing
posture, an entry in `docs/dependencies.md`) and a *measured coverage* exit criterion rather than a
completeness claim. The rest: `DebugSectionProvider` takes named byte ranges (not a container) so LE/MZ
is a new impl; unknown tags/forms/record IDs skip with a report as a *rule*, which is what lets the
326-ID catalogue land incrementally; `fasthash::FxHasher` + dense-vec per the perf log's own paid
lessons, one perf-log row per phase; and, since debug sections are the one input class guaranteed to
be hostile, explicit depth caps (stack exhaustion aborts and Rust can't catch it), no collection
sized from file data, visited sets on every traversal, `deny(indexing_slicing, unwrap_used)` on the
new modules, and `.gnu_debuglink`/build-id treated as attacker-controlled *paths* — no absolute, no
`..`, resolved only under the configured search roots.

DOS-era compiler formats (Watcom `-hw`/`-hd`/`-hc`, Borland TDS, CodeView appended to MZ/LE) are a
**later stage** with a designed-for slot: keep the section provider and the CodeView reader
container-agnostic, and most of that story falls out of the PE and DWARF phases — Watcom `-hd`
emits DWARF the same reader handles, and `-hc`/MS C emit the same CodeView `S_*`/OMF family.

Note for measurement: **no committed binary carries debug info** — no `-g` in
`oracle/analysis-corpus/build.sh`, and the DOS-era games have `e32_debuglen = 0` with no
CodeView/HLL marker — so this track needs its own corpus and does not perturb existing goldens.

## Recompile-emitter generalization (deferred by JD, 2026-08-17 — not a priority yet)

`war2_survey`/`recompile_check` carry WAR2.EXE inheritance that should become **per-target
(32-bit Watcom), not per-binary**: the emit/manifest/TU-assembly layer, the representability
contract (`build_prelude`'s closed vocabulary + `contract_violations` — widths are already a
target property, not a WAR2 one), the declaration safety net, and the standalone-scope
selection all generalize as "the Watcom-x86-32 emitter"; only the input loading and per-binary
bookkeeping are binary-specific. The ground-truth corpus's `watprog` column is the natural
second consumer that proves the split. Keep the printc separation rule while doing it: printc
stays the faithful Ghidra renderer; every compilability mechanism lives in the emitter layer
(or an `EmitChoices` arm), never in printc.

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

## Open defects found during the near-frontier argument session (2026-08-18)

- **E1010 regression specimen `02583`/`FUN_00066100`** (sb53, MISMATCH → COMPILE_FAIL):
  sharpened 2026-08-18 second pass — `pcVar5 = CONCAT11(..)` is a 2-byte PARTIAL WRITE
  into a 4-byte `code *`-typed HighVariable; printc names the whole variable where
  Ghidra prints partial-symbol syntax (`var._0_2_`, `PrintC::pushPartialSymbol` — itself
  uncompilable C, so the byte-exact route is contract/off-band, not a cast). Two real
  questions: why the merge united a 2-byte piece with the pointer-typed whole under the
  new dataflow (the upstream fix), and why the contract detector's partial-accessor net
  missed a partial WRITE (the tripwire fix). The standalone oracle is context-poor here
  (no function at the stored addresses, so no code* typing) — an app-oracle comparison
  is needed for the merge question.

- **Dropped call arguments at trial-machinery level** (specimen `FUN_00011954` @0x11954,
  fixture `ma00047` in the pinned tree's datatests): the oracle recovers
  `func_0x000594cc(xRam0008126c, 0x2b)`; mosura drops both args (EAX trial marked
  definitely-not-used, EDX trial deactivated between passes) and dead-codes the
  `MOV EDX,0x2b`. Trace-diff names the divergence neighborhood: Ghidra runs
  `RuleStoreVarnode`/`RuleSub2Add`/`RuleCollapseConstants` at each CALL pc (the
  return-address stores through the rule path) where mosura's `recover_stack` pre-model
  neutralized them; the composition difference feeds the ancestor/trial judgments.
  Near-frontier reach: `missing MOV Ereg,const` = 25 rows, plus knock-on missing
  PUSH/POP saves. E1082's neighborhood — instrument the trial D-flag judgment next.
- **Pipeline does not terminate on garbage decode** (found via the trace.rs arch bug: a
  32-bit fixture decoded with x86-64 tables spun 57 CPU-minutes). Ghidra bounds its
  mainloop; check whether mosura's restart/pass caps are ported everywhere.

## Open defects found during the E1032 instrument (2026-08-17)

- **`ground_truth_parity`: 4 failing tests — ALL RESOLVED (2026-08-17).** Four distinct roots,
  none of them the c370f1d deadcode sweeps per se (that bisect anchor held only for the comma
  tests; computed_goto was born failing at its own introduction commit):
  - `for_comma_condition_inline`: gutted dead ops in block op lists counted as statements in the
    structurer's `is_complex` (a dead `IntEqual out=None` flag compare), pushing the loop head
    past the threshold -> WhileDo printed in overflow syntax. Fixed: skip dead ops (Ghidra's
    `BlockBasic::isComplex` walks a live-only list). Oracle-verified: Ghidra prints the same
    for-loop with an EMPTY initializer, which exposed a second mis-port -- `findInitializer`
    requires a WRITTEN initializer (`block.cc:3229`); mosura's def-less carry printed
    `for (param_1 = param_1; ...)` self-assigns.
  - `loop_comma_condition_inline`: Ghidra freezes every collapse-time verdict at the FIRST
    structure build (`ActionBlockStructure::apply` returns early once built, blockaction.cc:2172)
    -- typically mainloop iteration 1, BEFORE delayed ram heritage merges a loop's global reload,
    so loopcomma's head counts 3 statements -> overflow `while(true)` form. mosura's re-deriving
    orientation builds recomputed `complex` on the late graph and flipped the verdict. Fixed:
    `Funcdata::structure_complex` pins the first collapse's verdicts, cleared exactly at
    `structure_reset()`. Both walk_ shapes now byte-match the oracle; the WAR2 nested-if family
    (14 EXACT) that briefly regressed under the dead-skip alone came back +1 (sb38: 586 EXACT).
  - `callee_register_return_is_recovered_with_its_argument`: the call-arg monotone union
    resurrected a POSITIONAL HOLE (`fillin_map` marks inactive trials between actives used AND
    active) as a phantom middle argument -- `func(xRam, param_2, param_2)`. Fixed: the union's
    evidence bar is the PRE-FILLIN active verdict (`check_input_trial_use`'s "the caller placed
    this value"), matching the adaptation's own stated rationale.
  - `computed_goto_table_is_refused_once_function_bodies_are_current`: `RuleConcatCommute` fired
    on `PIECE(#0, x & 3)` because mosura's `is_free` excludes constants where Ghidra's
    `Varnode::isFree` (= `!(written|input)`, varnode.hh:238) includes them -- the `hi->isFree()`
    guard (ruleaction.cc:4530) is what reserves the constant-hi PIECE for `RuleConcatZero`'s
    clean `INT_ZEXT`. The manufactured `& 0xffffffff00000003` mask defeated the jump-table
    index-range analysis; the BRANCHIND fell back to an indirect call, no ComputedJump refs
    formed, and the AddressTable collision rule had nothing to refuse. Fixed at the rule site
    (free-or-constant guard); oracle-verified (full 4-case switch recovered).

- **`is_free` vs Ghidra `Varnode::isFree` — AUDIT DONE (2026-08-17).** The definition is now
  Ghidra's (`!(WRITTEN|INPUT)`, varnode.hh:238 — constants ARE free). What the audit found:
  Ghidra has THREE distinct predicates and mosura's old `!(INSERT|CONSTANT)` had conflated them:
  (a) `isFree` — 100+ translated rule guards, now correct by construction after the flip;
  (b) `isHeritageKnown` (insert|constant|annotation) — 15 rules use it; 13 ports were already
  faithful, `RulePropagateCopy` spelled it `is_free` (blocked constant propagation post-flip;
  converted) and `RuleLessEqual` was missing both operand guards entirely (added,
  ruleaction.cc:2270);
  (c) `printRaw`'s literal `(flags&(insert|constant))==0` free-tag — restored as the exact
  expression at the print site.
  Two `makeFree` mis-ports fixed (`new_output`/`op_set_output` left INSERT on displaced
  outputs; varnode.cc `makeFree` clears insert|input|indirect_creation) — restoring the
  invariant `INSERT <=> (WRITTEN|INPUT)` that makes the flip exact. The `calls_awaiting_output`
  ordering-repair predicate was silently keying on that mis-port artifact AND matching every
  constant argument; respelled as `is_free() && !is_constant()`. RESOLVED (2026-08-17), the addrtied follow-up: the
  divergence was the ACCESSOR, not the flags — Ghidra `Varnode::isAddrTied` (varnode.hh:250) is
  the COMPOUND `(flags & (addrtied|insert)) == (addrtied|insert)`, so a flagged-but-FREE global
  answers false (this is why CAPTURE_FLAGS_AT printed `addrtied=0` for ZF and why the loopcomma
  investigation's register-addrtied theory kept failing). mosura's flag-only accessor now
  matches the compound; flag SETTING (spacebase/ram at alloc, registers never) already agreed.
  Verdict-neutral everywhere: full suite green, fixture corpus 0.9700, WAR2 sb40 zero verdict
  transitions AND zero changed emissions vs sb39.
  Measured: fixture corpus 0.9700 held exactly; WAR2 sb39 zero verdict
  transitions (586 EXACT / 14 COMPILE_FAIL) with 38 emissions improved (deeper propagation);
  full suite green in the canonical config.

- **Environment tangle — RESOLVED (2026-08-17).** The two "env-dependent" tests were: (a)
  `disasm_pcode_ratchet` missing four languages (ARM/6502/MIPS/PowerPC) from the vendored
  subset — now vendored byte-verbatim from the pin (`verify-vendored-ghidra.sh` green, ratchet
  floor raised 254 → 338 and passing with NO env); (b) `pointer_in_integral_op_is_cast` was not
  flaky at all — it SILENTLY SKIPPED without a checkout (direct `ghidra_src().join(...)` with
  no vendored fallback) and genuinely failed when run: its expected string pinned a
  pre-ConcatCommute rendering (`(uint8)param_1 & 0xf`), while the oracle prints
  `(uint4)param_1 & 0xf` inside a zext — expectation updated to the oracle's current form. All
  16 direct-path sla loads (10 tests + 6 examples) now route through `paths::language_dir`, so
  none can silently skip again. The `/data/tools` pinned checkout had a stale local injection
  (`x86-32-watcom.cspec` + ldefs edit, superseded by `specs/`) — restored to pristine.

- **Port I/O ops dropped in `FUN_0005c5ec` — FIXED (2026-08-17).** Not a dataflow loss: the
  final IR carried every CALLOTHER; printc's statement catch-all required an OUTPUT to emit, so
  a void userop (`out(port, val)`) produced no statement — Ghidra's `emitExpression` no-output
  branch (printc.cc:2273) prints it bare. Plus `Callother` was missing from the call-class
  (`isCall()`) arms: `baseExplicit`'s call-output-explicit rule and `checkImpliedCover`'s
  call-crossing list both include it (`TypeOpCallother` opflags `special|call|nocollapse`,
  typeop.cc:814). 112 WAR2 emissions gained their previously-dropped I/O (02334's `out()`
  sightings were expression-position survivors only); zero verdict transitions (585 EXACT / 14
  COMPILE_FAIL hold), dominant-cause "missing" 921 → 906, fixture corpus 0.9679 unchanged.
- **Persist-store ordering vs byte-exactness** (the −5 EXACT from the deadcode-blanket
  retirement, sb35): when a global store's value survives only through the call-INDIRECT /
  return-copy chain (RulePropagateCopy legitimately rewires the INDIRECT input — Ghidra's marker
  guards permit it, its C prints the same late/swapped order, FUN_000165f4 oracle-verified), the
  materialized statement order no longer matches the original store schedule. Byte-exact wants
  the original order; Ghidra-fidelity produces the swap. Emitter-side follow-up (an EmitChoices
  arm reordering independent persist stores to their original addresses, or acceptance).
