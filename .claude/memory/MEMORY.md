# Memory index

One line per memory — a HOOK, not content. Detail lives in the topic files + git history + TODO.md.
Keep this current, not historic. If a line grows past ~1.5 lines, move the detail into its file.

## How to work
- [memory-lives-in-the-repo](memory-lives-in-the-repo.md) — **⭐ USER RULE 2026-08-07: memory is VERSIONED IN THE REPO at `.claude/memory/`, never machine-local. Commit it.**
- [agents-must-match-my-model-exactly](agents-must-match-my-model-exactly.md) — **⭐ USER RULE 2026-08-07: every sub-agent runs MY exact model (Opus 5, `claude-opus-5[1m]`) — pass `model: "opus"` and VERIFY the id verbatim.**
- [always-keep-the-task-list-current](always-keep-the-task-list-current.md) — **⭐ USER RULE 2026-08-07: the task list is updated AS STATE CHANGES, never batched when asked.**
- [perf-iterate-on-an-mve-or-a-profile](perf-iterate-on-an-mve-or-a-profile.md) — **⭐ USER RULE 2026-08-07: for PERF iterate on an MVE or a PROFILE. A cap below every hypothesis answers nothing.**
- [probe-with-timeouts-dont-wait-for-runs](probe-with-timeouts-dont-wait-for-runs.md) — **⭐ USER RULE 2026-08-07: run it PARTIALLY and kill it with a timeout. A capped run still answers the question; never report it as a pass.**
- [redirect-output-then-read-the-file](redirect-output-then-read-the-file.md) — **⭐ USER RULE 2026-08-07: redirect every run to a FILE, then query the file. NEVER re-run to re-read output.**
- [i-direct-the-agent-not-the-reverse](i-direct-the-agent-not-the-reverse.md) — **⭐ USER RULE 2026-08-07: I direct the agent, I always know what it is doing, and DOUBT ⇒ kill it and restart with a known task.**
- [hard-rules-never-stop-one-agent](hard-rules-never-stop-one-agent.md) — **THREE ABSOLUTE user rules: never stop · exactly one agent · remove-before-create.**
- [dont-stop-take-first-option](dont-stop-take-first-option.md) — never stop to ask; take the first/recommended option and keep executing.
- [default-to-recommended-dont-block](default-to-recommended-dont-block.md) — surface status, not questions.
- [finish-parked-before-new](finish-parked-before-new.md) — **FINISH parked/built-but-unintegrated code before new work.**
- [single-agent-protocol](single-agent-protocol.md) — one background agent; warm-resume by message; `TaskStop` kills phantoms.
- [goal-is-the-binary-not-ghidra](goal-is-the-binary-not-ghidra.md) — **target = exactness with the ORIGINAL BINARY; Ghidra-faithfulness is the METHOD.**
- [direction-faithful-port](direction-faithful-port.md) — faithful structural port; corpus is a diagnostic, not the target.
- [faithful-ports-land-not-held](faithful-ports-land-not-held.md) — a faithful port LANDS; only wrong-code/hard-test breaks block.
- [port-all-faithful-rules](port-all-faithful-rules.md) — port EVERY faithful rule; nothing is grandfathered.
- [faithful-type-of-wrong-ir](faithful-type-of-wrong-ir.md) — ugly render from a faithful layer = wrong upstream IR; fix the IR.
- [gate-byte-identical-only](gate-byte-identical-only.md) — self-approve only on byte-IDENTICAL corpus; any fixture move is gated.
- [numbers-stale-unless-sha-stamped](numbers-stale-unless-sha-stamped.md) — every number is STALE unless @sha==HEAD.
- [war2-issues-become-source-tests](war2-issues-become-source-tests.md) — **every WAR2 issue → a self-compiled Watcom source test as ground truth.**
- [mve-obvious-version-tests-nothing](mve-obvious-version-tests-nothing.md) — **⭐ 4/4: the obvious MVE passes unfixed; write it, RUN it, then sharpen.**
- [mve-first-then-solve-the-mve](mve-first-then-solve-the-mve.md) — **⭐ USER RULE 2026-08-05: MVE FIRST, then solve the MVE — now AGENTS.md directive 6. Carries the MVE-building traps.**
- [could-it-have-come-out-otherwise](could-it-have-come-out-otherwise.md) — **⭐ PRE-FLIGHT: a predicate whose answer is fixed in advance measures nothing (4 in one day).**
- [self-compiled-ground-truth](self-compiled-ground-truth.md) — self-authored programs per compiler as ground truth over Ghidra.
- [book-assume-tool-finished](book-assume-tool-finished.md) — write the mosura-book as docs of a FINISHED tool.
- [direction-analysis-port](direction-analysis-port.md) — analysis track A0–A7 DONE. CLOSED — do not re-raise.

## Primary track: retire the inventions
- [retirement-track-wave1](retirement-track-wave1.md) — **⭐ WAVE 1 A3 `9439fcf`: the held stackptr regression was CURED by the heritage core; 3820 stack trials vs a structural ZERO. New class: undefined `goto` labels.**
- [direction-retire-inventions-first](direction-retire-inventions-first.md) — **★ USER PIVOT 2026-07-29: retiring inventions is THE primary track; WAR2-specific work parked. Protocol + 4 waves.**
- [hardcoded-x86-64-vs-cspec-class](hardcoded-x86-64-vs-cspec-class.md) — **⭐ THE CLASS: mosura hardcodes x86-64 registers where Ghidra QUERIES THE CSPEC — fatal on x86-32.**
- [adaptations-inventory](adaptations-inventory.md) — the audited list of every remaining adaptation, file:line cited, bounded vs deep.
- [bounded-levers-exhausted](bounded-levers-exhausted.md) — bounded corpus levers EXHAUSTED; don't force deep foundations autonomously.

## Active campaign: WAR2 byte-exact
- [war2-byte-exact-campaign](war2-byte-exact-campaign.md) — **ACTIVE SUSTAINED**: drive WAR2 byte-exact via faithful ports; lead holds delegated gating.
- [war2-band-root-cause](war2-band-root-cause.md) — **⭐ the 0-16% band is hardcoded RSP=0x20 vs the cspec `<stackpointer>`, not a codegen wall.**
- [watcall-killedbycall-too-aggressive](watcall-killedbycall-too-aggressive.md) — **⭐ cspec says killedbycall [EAX,ECX,EDX]; wcc386 keeps EDX LIVE across an indirect call → INFINITE LOOPS. No Ghidra watcom cspec = no oracle.**
- [subregister-write-not-merged](subregister-write-not-merged.md) — **⭐ the call-dropping class: a sub-register write is not merged into the containing wide read, so it binds a stale def.**
- [war2-subregister-heritage-rootcause](war2-subregister-heritage-rootcause.md) — the same defect measured: 92 fns / 246 calls; `determinedbranch` is the executioner, not the culprit.
- [absolute-vs-differential-wrongcode](absolute-vs-differential-wrongcode.md) — **⭐ measure ABSOLUTELY; a differential scan cannot see a defect present on both sides. Counting traps inside.**
- [war2-relocation-seeding](war2-relocation-seeding.md) — **⭐ `ef98638` LE fixups seed disassembly: 1631→1965. THE RULE: score FPs by BODY INTRUSION, not by "not in Ghidra".**
- [war2-address-table-port](war2-address-table-port.md) — **⭐ `93ca489` AddressTableAnalyzer: 1308→1653, 1 FP. ⚠️ `-processor` forces cspec=windows → 1944; auto-detect → 2145.**
- [ghidra-never-makes-functions-from-data-pointers](ghidra-never-makes-functions-from-data-pointers.md) — **⭐ data-side analyzers DISASSEMBLE pointer targets and create NO function; the yield is the CASCADE.**
- [war2-missing-calls-class](war2-missing-calls-class.md) — the RULE (measure vs the binary). ⚠️ its "41% / 455 fns" figure is RETRACTED — linear-sweep artifact.
- [reftype-is-post-override-not-the-instruction](reftype-is-post-override-not-the-instruction.md) — **⭐ reftypes are analysis OUTPUT — an UNCONDITIONAL_CALL ref can sit on a `jmp`.**
- [command-vs-notification-channel](command-vs-notification-channel.md) — **⭐ Ghidra's disassemble/createFunction are COMMANDS, not codeDefined/functionDefined; the channel model DROPS them.**
- [r-min-range-iteration-misport](r-min-range-iteration-misport.md) — **⭐ `set.ranges()` + `r.min` skips every adjacent address; Ghidra iterates ADDRESSES (`<= 4` cut).**
- [war2-mz-inline-call-parameters](war2-mz-inline-call-parameters.md) — **⭐ the war2 MZ `0x13a56` thunks are followed by a 2-byte INLINE PARAMETER; decoding it destroys a real instruction.**
- [listing-gate-held-fix](listing-gate-held-fix.md) — **⭐ `9d2f0e9`+`71876a2`: gate committed RED+`#[ignore]`d; fix HELD in `held-patches/`; unblocker = a fall-through override model.**
- [shared-return-cursor-cache-is-semantic](shared-return-cursor-cache-is-semantic.md) — SharedReturnAnalysisCmd's functionBefore/AfterSrc caches CHANGE the answer; open gap = invocation granularity.
- [thunk-resolution-runs-before-the-body](thunk-resolution-runs-before-the-body.md) — **⭐ `69cf941`: a jump-only entry is a THUNK; Ghidra creates its target's function BEFORE storing the body. Run it after the walk and every thunk vetoes its own target. NOT shared return.**
- [war2-tailjmp-mve](war2-tailjmp-mve.md) — the tail-call MVE; `-oc` suppresses the shape, and C can't make a forward tail jmp.
- [war2-per-function-ghidra-oracle](war2-per-function-ghidra-oracle.md) — **⭐ RECIPE: ask Ghidra about any WAR2 function despite the DOS/4GW-LE loader problem.**
- [war2-guardreturns-port](war2-guardreturns-port.md) — **⭐ `6e1b113` return candidates from the cspec; headline 1→9 byte-clean, narrow-switch bug closed.**
- [structured-graph-is-a-list-not-a-root](structured-graph-is-a-list-not-a-root.md) — **⭐ `282bf51`: `emitBlockGraph` prints EVERY top-level component; we printed one and dropped 45 blocks. reached==cfg 45→0, CFAIL 102→95.**
- [guardreturns-port-held](guardreturns-port-held.md) — its gating argument: the blocking rule stops SILENT undiagnosed wrong code, not diagnosed+owned regressions.
- [first-exact-lane](first-exact-lane.md) — **⭐ the lane paid: drive ONE function end-to-end, blockers in order. Don't generalize before one EXACT.**
- [war2-exact-reference-mismatch](war2-exact-reference-mismatch.md) — **⭐ EXACT must compare the FIXUP-APPLIED image, not raw on-disk bytes.**
- [war2-survey-manifest-idx-trap](war2-survey-manifest-idx-trap.md) — **key surveys on the FUN_ name in each .c, NEVER the manifest idx.**
- [war2-recompile-survey](war2-recompile-survey.md) — the recompilation-parity survey; doc `docs/war2-function-status.md`, recipe `docs/war2-recompile-remeasure.md`.
- [war2-survey-artifacts-stamped](war2-survey-artifacts-stamped.md) — **⭐ `4f929e8` emits are commit-stamped; bare `src/` was a 23.6% BLEND. war2-survey/ is NOT in git.**
- [war2-stackptr-wrong-code](war2-stackptr-wrong-code.md) — the stackptr patch's historical call-drop; only the CALL-COUNT SCAN caught it. Re-tested in wave 1.
- [war2-stackpointer-rootcause](war2-stackpointer-rootcause.md) — the live file:line deep-dive map for the RSP/ESP arc.
- [rule-indirect-collapse-unblocks-stackptr](rule-indirect-collapse-unblocks-stackptr.md) — the 25 panics were a MISSING RULE (`RuleIndirectCollapse`, `006fabc`), not a flag.
- [war2-remediation-campaign](war2-remediation-campaign.md) — remediation #1-#3 complete; remaining gap deep.
- [war2-le-fixups-root-cause](war2-le-fixups-root-cause.md) — `cbd6295`: `load_le` applies LE fixups → 541→1279 funcs.
- [war2-function-set-ground-truth](war2-function-set-ground-truth.md) — **⭐ WAR2 truth = the expert tracker (2120), NOT Ghidra 1944; real gap 820 not 641.**
- [war2-tracker-anchors-mid-prologue](war2-tracker-anchors-mid-prologue.md) — **⭐ the tracker records save-first entries at the `push ebp`; score SHIFT-TOLERANTLY or overstate the gap by 50. Real gap 42, not 92. A DISTRIBUTION can be an artifact too.**
- [war2-dos4gw-le](war2-dos4gw-le.md) — **⭐ warcraft2-re's ELF32 wrapper gives Ghidra FULL whole-image analysis — it beats the per-function recipe.**
- [war2-branchind-classification](war2-branchind-classification.md) — the 9 unrecovered BRANCHIND classified; loader ruled out.

- [war2-pragmatism-over-faithfulness](war2-pragmatism-over-faithfulness.md) — **⭐ USER RULE 2026-08-05: for WAR2 PRAGMATISM wins — but beyond-Ghidra has NO ORACLE: validate against a 2nd oracle, stay ADDITIVE.**

## Function discovery (analysis lane)
- [command-queue-modelled-as-change-channel](command-queue-modelled-as-change-channel.md) — **⭐⭐ THE ROOT CAUSE: Ghidra's `disassemble()`/`createFunction()` are COMMAND-QUEUE pushes; we model them as change notifications, so they silently drop. Explains the 374-function listing hole AND the re-fire loop.**
- [empty-bodies-take-the-permissive-branch](empty-bodies-take-the-permissive-branch.md) — **⭐ an empty body doesn't blur a ported body query, it INVERTS it to the permissive branch; the fix can legitimately REMOVE refs. Carries the `added()`-called-directly vacuity trap.**
- [regenerate-before-adopting-a-classifier-change](regenerate-before-adopting-a-classifier-change.md) — **⭐ a "more principled" truth-class change would have dropped EVERY entry point from the recall gate corpus-wide; only regenerating first showed it.**
- [self-compiled-gate-measures-your-imagination](self-compiled-gate-measures-your-imagination.md) — **⭐ 0-spurious across 17 known binaries was STRUCTURALLY BLIND; an unanchored pattern needs a POPULATION score on a real binary. Push-order does not rescue it.**
- [decoded-not-in-function-needs-address-table](decoded-not-in-function-needs-address-table.md) — **⭐ only AddressTableAnalyzer makes code DECODED-but-in-no-function; the COMPILER FLAG is what lets the gate fail.**
- [watcom-901-anchor-inversion](watcom-901-anchor-inversion.md) — **⭐ 9.01 emits `SETcc;MOVZX` + `CDQ;IDIV` too: they mark the lineage's OUTER ENDS, not Open Watcom.**

## Tooling / gotchas
- [fast-iteration-skip-the-whole-binary-tests](fast-iteration-skip-the-whole-binary-tests.md) — **⭐ inner loop 367s -> 27s by SKIPPING 4 whole-binary tests at the CLI. Caching across tests does NOT help — cargo already parallelises.**
- [worktree-needs-ghidra-src-or-ratchet-lies](worktree-needs-ghidra-src-or-ratchet-lies.md) — **⭐ a /tmp worktree silently drops to 15 vendored languages and `disasm_pcode_ratchet` calls it a REGRESSION; set `GHIDRA_SRC`.**
- [pattern-gate-cspec-routing](pattern-gate-cspec-routing.md) — **⭐ a Watcom-fixture gate silently measures the GCC pattern file (corpus Watcom ELFs are `cspec=gcc`); call-reachable recall is vacuous.**
- [load-the-artifact-directly](load-the-artifact-directly.md) — **the constructive half: when a fixture cannot reach the code, a test that loads the artifact BY PATH is the real gate, not a fallback.**
- [inert-is-not-thread-safe](inert-is-not-thread-safe.md) — **⭐ inert-when-unset ≠ safe-under-concurrency; an env-var test hook turned the suite red. Remove shared state, do not guard it.**
- [oracle-same-question-not-just-same-tool](oracle-same-question-not-just-same-tool.md) — **⭐ Rule Zero's half two: verify Ghidra was ASKED THE SAME QUESTION. The per-function oracle zeroes absent callees' params; 3 sessions read that as our bug.**
- [landed-means-reachable-from-a-ref](landed-means-reachable-from-a-ref.md) — **a battery-green 8-commit series sat on an UNREFERENCED detached HEAD. `git branch --contains` before declaring a land.**
- [invention-inventory-empty](invention-inventory-empty.md) — **⭐ ALL 3 invented rules retired @147adaf; trace-names.py's ADAPTATION list is EMPTY (148/148) and is the standing check.**
- [address-equality-is-not-op-equality](address-equality-is-not-op-equality.md) — trace-diff's per-address columns LOCALIZE; they don't prove the same op reached the same rule. Dump both op shapes first.
- [typeprop-channel-and-width-rootcause](typeprop-channel-and-width-rootcause.md) — **⭐ TYPEPROP_DEBUG is a SECOND Ghidra trace channel; it EXONERATED `type_order` — the divergence is varnode WIDTH, from SubVariableFlow.**
- [trace-diff-keys-mechanism](trace-diff-keys-mechanism.md) — **trace-diff keys on the Ghidra CLASS, not the name; OPACTION_DEBUG is BLIND to type inference — never read typing from a trace.**
- [invention-worse-at-its-own-job](invention-worse-at-its-own-job.md) — an invented rule was WORSE than Ghidra's real one at its own justifying fixture; when retiring, find the faithful rule already covering it.
- [trace-diff-first-not-fifth](trace-diff-first-not-fifth.md) — **run `scripts/trace-diff.sh` FIRST on any "why doesn't mosura produce X".**
- [rule-trace-diff-tool](rule-trace-diff-tool.md) — the trace-diff + `oracle/capture_trace` tooling; oracle final IR = `capture --ir -`.
- [gauge-counting-traps](gauge-counting-traps.md) — **check the opposite-sign twin, and check SET MEMBERSHIP, not totals.**
- [cast-census-is-per-line](cast-census-is-per-line.md) — **⭐ GOTCHA: `cast-census.py` reads PER LINE, so mosura-vs-GHIDRA cast counts are biased; mosura-vs-mosura deltas stay sound.**
- [print-raw-has-no-dead-filter](print-raw-has-no-dead-filter.md) — **GOTCHA: `print_raw` lists DESTROYED ops as bare opcodes; corpses read as live.**
- [measurement-determinism-first](measurement-determinism-first.md) — make measurements deterministic BEFORE chasing an apparent regression.
- [generated-artifact-drift](generated-artifact-drift.md) — never hand-edit a GENERATED file; fix the generator, stamp the input hash.
- [corpus-oracle-ignores-prototypes](corpus-oracle-ignores-prototypes.md) — tools linking libdecomp_dbg.a must match `-DCPUI_DEBUG -D__TERMINAL__`.
- [corpus-windows-x64-fixtures](corpus-windows-x64-fixtures.md) — 4 fixtures are Windows-x64 ABI, out of SysV scope; caps the gauge below 1.0.
- [oracle-capture-decodererror](oracle-capture-decodererror.md) — `oracle/capture.cc` +17 UNCOMMITTED (lead gates); harness takes GHIDRA_SRC root, not a `.sla`.
- [ghidra-dependency-pin](ghidra-dependency-pin.md) — `scripts/setup-ghidra.sh` pins tag Ghidra_12.0.3_build @09f14c92 + compiles the `.sla`.
- [analysis-external-toolchains](analysis-external-toolchains.md) — /data build caches, ~/tools symlinks, historical compilers, Ghidra DEV dist + JDK21.
- [mosura-perf-worktree](mosura-perf-worktree.md) — MOSURA_PERF timing tooling; candidates in docs/perf-log.md.
- [mosura-book](mosura-book.md) — Typst book at /home/jd/projects/mosura-book.
- [analysis-unblocked-sweep-0723](analysis-unblocked-sweep-0723.md) — the 2026-07-23 analysis sweep; all items landed.

## Architecture / inventory
- [heritage-core-campaign](heritage-core-campaign.md) — **THE CAMPAIGN. Stage A + Stage B + the spacebase half all LANDED; `held-patches/` is the durable patch home.**
- [variablepiece-extended-cover](variablepiece-extended-cover.md) — `be13a04` extended cover. **FAITHFUL ≠ COMPILABLE are separate axes.**
- [d-backlog-landed](d-backlog-landed.md) — D2–D6 mis-port backlog ✅ COMPLETE (SHAs + residuals in file). Spec history: [decompiler-misport-backlog](decompiler-misport-backlog.md).
- [actionsetcasts-campaign](actionsetcasts-campaign.md) — Brick 1 `3579ac3`; Brick 2 gated behind retiring print-time re-inference.
- [base-getinputcast-was-the-catchall](base-getinputcast-was-the-catchall.md) — **⭐ `ab6ea9c`: `_ => None` was the opposite of Ghidra's BASE `getInputCast` default (693 firings); the PTRADD refit fixed a 4× MIS-SCALING.**
- [ptrsub-refit-inert-spacebase](ptrsub-refit-inert-spacebase.md) — the sibling refit is INERT (536/536 true); its blocker is the ScopeLocal SYMBOL QUERY. Don't generalise from PTRADD.
- [fid-port-track](fid-port-track.md) — faithful FID fingerprinting port. PLAN ONLY; Stage 0 needs SLEIGH masks.

## Live status
- [live-status](live-status.md) — branch pointers, corpus/suite/byte-clean numbers, the gauge command, and where the gauge inputs live. **Every number is STALE unless @sha==HEAD.**

## Live campaign topic files (open follow-ons in-file)
- [task8-mainloop-repeat](task8-mainloop-repeat.md) — mainloop cadence LIVE. Open: RuleDoubleIn/Out, isUnmappedUnaliased carve-out, RulePtraddUndo/PtrsubUndo.
- [merge-family-cluster](merge-family-cluster.md) — Bricks 1-3 + directwrite + cspec1 done. PARKED: mergeIndirect, processMultiplier (C-cluster).
- [task19-p7-plan](task19-p7-plan.md) — P7 complete. Open: compound-condition for-recovery, loop-2 INT_AND/BOOL_AND dataflow bug.
- [task22-typespacebase-campaign](task22-typespacebase-campaign.md) — #22-A+B complete. Open: isUnmappedUnaliased param carve-out.
- [switchloop-residual-c-donothing](switchloop-residual-c-donothing.md) — `78de54a`. Open: mergeOp blind-trim, ActionDominantCopy/CopyMarker, mergeIndirect.
- [switchloop-dup-propagatecopy](switchloop-dup-propagatecopy.md) — ActionSwitchNorm CLOSED. Open: jumptable action-group (coreaction.cc:5434).
- [task2-p6-prototypes-plan](task2-p6-prototypes-plan.md) — P6 complete; concatsplit unref-declaration gap in-file.
- [task21-floatcast-return-decomp](task21-floatcast-return-decomp.md) — CLOSED; residuals are weak-type + fVar3 temp.
- [task4-heritage-guard-collect-plan](task4-heritage-guard-collect-plan.md) — guardStores+guardCalls landed; remainder gated.
- [task4-comparison-normalization](task4-comparison-normalization.md) — Phase-1c comparison normalization; entry = cancel+repair of [[printc-structuring-adaptation-conflicts]].
- [task28-partialsplit-deadstore-escaped-stack](task28-partialsplit-deadstore-escaped-stack.md) — DEEP/LOW-VALUE; never run standalone.
- [consume-model-misport](consume-model-misport.md) — ✅ ARC CLOSED `608d7d3`.

## Landed arcs
- [landed-arcs](landed-arcs.md) — the 15 CLOSED porting arcs, one line each with the landing SHA and any deferred remainder.

## Pre-existing (were already versioned here)
- [mosura-project](mosura-project.md) — Rust port of Ghidra logic; pinned to Ghidra 12.0.3 (matches MCP oracle); SLEIGH-engine-first test-baseline strategy.
- [respect-plan-decisions](respect-plan-decisions.md) — respect agreed plan decisions; ask approval before changing any.
