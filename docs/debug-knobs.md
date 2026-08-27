# The `MOSURA_*` environment names: every one classified (review R6, commit 3)

*The inventory at a531553 (before R6): 81 names, 208 `eprintln!` in crates/mosura/src, 141 `std::env::var` reads outside paths.rs. Four kinds: a DEBUG PRINT gate (read at the print site — migrated to `crate::debug`, `MOSURA_DEBUG=topic,..`), a BEHAVIOUR KNOB (changes what the decompiler, the survey or an oracle does — decided one by one: an axis/option with a doc, or deleted with its branch), a PATH (configuration, paths.rs, untouched), a TEST HOOK / INSTRUMENT (kept, documented). The emit-layer decisions are executed in R6; the others are listed for the ledger. Evidence: the read sites at a531553.*

| name | kind | sites (file:line at a531553) | decision |
|---|---|---|---|
| `MOSURA_ALIAS_DEBUG` | debug print gate | decompile/varnodeprops.rs:64 | MIGRATE in R6 commit 4 (its subsystem's topic), text verbatim after the old prefix -- R6 (4) |
| `MOSURA_ANALYSIS_TRACE` | debug print gate | analysis/manager.rs:279 analysis/manager.rs:283 | MIGRATE in R6 commit 4 (its subsystem's topic), text verbatim after the old prefix -- R6 (4) |
| `MOSURA_AOU_PC` | debug print with a value | decompile/recover.rs:624 | DECIDE later (not emit): a trace filter by pc inside `affects_ordering`; a `debug::param` candidate or delete -- listed |
| `MOSURA_ARG_DEBUG` | debug print gate | analysis/decompiler.rs:470 analysis/decompiler.rs:491 decompile/build.rs:213 decompile/heritage.rs:1545 | MIGRATE in R6 commit 4 (its subsystem's topic), text verbatim after the old prefix -- R6 (4) |
| `MOSURA_BLOCKSET` | debug print gate (emit) | decompile/printc.rs:4810 decompile/printc.rs:4811 decompile/printc.rs:4830 decompile/printc.rs:4841 decompile/structure. | MIGRATED, R6 commit 2 -> `MOSURA_DEBUG=printc` -- done |
| `MOSURA_CALLARGS` | debug print gate (emit) | decompile/printc.rs:2175 | MIGRATED, R6 commit 2 -> `MOSURA_DEBUG=printc` -- done |
| `MOSURA_CALLEE_EFFECTS` | behaviour knob (analysis) | analysis/decompiler.rs:289 analysis/decompiler.rs:308 | DECIDE later (not emit): `=0` disables a landed pass (callee effects) -- an A/B switch; becomes an analysis option next to DISABLE_ANALYZERS or goes -- listed |
| `MOSURA_CFG` | debug print gate (emit) | decompile/varmap.rs:859 decompile/structure.rs:3167 decompile/structure.rs:3196 decompile/structure.rs:3204 | MIGRATED, R6 commit 2 -> `MOSURA_DEBUG=structure` -- done |
| `MOSURA_CNV_EXE` | path | paths.rs:179 paths.rs:182 analysis/loader/pe.rs:248 | paths.rs configuration, untouched |
| `MOSURA_COLLAPSE` | debug print gate (emit) | decompile/structure.rs:3377 | MIGRATED, R6 commit 2 -> `MOSURA_DEBUG=structure` -- done |
| `MOSURA_COMCOM32_EXE` | path | paths.rs:193 paths.rs:196 | paths.rs configuration, untouched |
| `MOSURA_COMPLEX` | debug print gate (emit) | decompile/structure.rs:3261 decompile/structure.rs:3271 decompile/structure.rs:3300 | MIGRATED, R6 commit 2 -> `MOSURA_DEBUG=structure` -- done |
| `MOSURA_CONDEXE_DEBUG` | debug print gate | decompile/condexe.rs:1133 | MIGRATE in R6 commit 4 (its subsystem's topic), text verbatim after the old prefix -- R6 (4) |
| `MOSURA_COND_DEBUG` | debug print gate (emit) | decompile/printc.rs:2596 | MIGRATED, R6 commit 2 -> `MOSURA_DEBUG=printc` -- done |
| `MOSURA_CONSTCHECK` | debug print gate | decompile/funcdata.rs:885 decompile/funcdata.rs:897 decompile/funcdata.rs:900 decompile/funcdata.rs:1778 | MIGRATE in R6 commit 4 (its subsystem's topic), text verbatim after the old prefix -- R6 (4) |
| `MOSURA_CONSTPTR_DEBUG` | debug print gate | decompile/constantptr.rs:225 decompile/constantptr.rs:250 | MIGRATE in R6 commit 4 (its subsystem's topic), text verbatim after the old prefix -- R6 (4) |
| `MOSURA_CP_PROBE` | debug print gate | analysis/analyzers/mod.rs:957 | MIGRATE in R6 commit 4 (its subsystem's topic), text verbatim after the old prefix -- R6 (4) |
| `MOSURA_DEADCODE_DEBUG` | debug print gate | decompile/deadcode.rs:30 decompile/deadcode.rs:33 | MIGRATE in R6 commit 4 (its subsystem's topic), text verbatim after the old prefix -- R6 (4) |
| `MOSURA_DEBUG` | facility |  | the facility itself (`crate::debug`, R6 commit 1): `topic,..|all`, read once |
| `MOSURA_DISABLE_ANALYZERS` | analysis option | analysis/manager.rs:249 analysis/overrides.rs:3 analysis/overrides.rs:48 analysis/overrides.rs:58 | KEEP, documented: Ghidra's per-analyzer switch (`analyzeHeadless -preScript`), thread override + env fallback (`analysis::overrides`) -- listed |
| `MOSURA_DISTRIB` | debug print gate | decompile/ptrarith.rs:39 decompile/ptrarith.rs:492 decompile/ptrarith.rs:870 decompile/ptrarith.rs:1314 decompile/ptrari | MIGRATE in R6 commit 4 (its subsystem's topic), text verbatim after the old prefix -- R6 (4) |
| `MOSURA_EFFECTS_DEBUG` | debug print gate | analysis/decompiler.rs:314 analysis/decompiler.rs:590 analysis/decompiler.rs:642 | MIGRATE in R6 commit 4 (its subsystem's topic), text verbatim after the old prefix -- R6 (4) |
| `MOSURA_EMIT_DEBUG` | debug print gate (emit) | recompile/recovery.rs:9 recompile/recovery.rs:123 | MIGRATED, R6 commit 2 -> `MOSURA_DEBUG=recover` -- done |
| `MOSURA_FID_DIR` | path | paths.rs:115 paths.rs:118 paths.rs:135 paths.rs:137 | paths.rs configuration, untouched |
| `MOSURA_FILLIN_DEBUG` | debug print gate | decompile/fspec.rs:395 | MIGRATE in R6 commit 4 (its subsystem's topic), text verbatim after the old prefix -- R6 (4) |
| `MOSURA_FRAME_DEBUG` | debug print gate (emit) | decompile/emit/arms/frame_fill.rs:60 decompile/emit/arms/frame_fill.rs:74 decompile/emit/arms/frame_fill.rs:109 | MIGRATED, R6 commit 2 -> `MOSURA_DEBUG=frame-fill` -- done |
| `MOSURA_GT_DEBUG` | debug print gate | recompile/groundtruth.rs:825 | MIGRATE in R6 commit 4 (its subsystem's topic), text verbatim after the old prefix -- R6 (4) |
| `MOSURA_GT_RAW` | debug print with a value | recompile/groundtruth.rs:554 | KEEP as a documented hook for now: prints one function's raw IR in the gt oracle (`=<symbol>`); candidate for `debug::param` later -- listed |
| `MOSURA_HIGH_DEBUG` | debug print with a value (emit) | decompile/printc.rs:3410 decompile/printc.rs:3413 | DELETE `debug_high_classes` and its call: a one-off merge-grouping view keyed by a register offset, no reader since the split-local rounds; if wanted again it is a `debug::param` design, not an env var -- R6 (3), executed |
| `MOSURA_ILV_CENSUS` | debug print gate (example: war2_survey) | examples/war2_survey.rs (the interleave census) | MIGRATED, R6 commit 3b -> `MOSURA_DEBUG=recover`; the census also reports the orders `interleave_orders` would apply (the parked lever's caller) -- done |
| `MOSURA_ILV` | behaviour knob (emit) | recompile/recovery.rs:104 recompile/recovery.rs:105 | DELETE the switch and its branch: `=1` enabled the blind interleave form, measured 2026-08-22 as a loser and OFF by default; `interleave_orders` stays exercised by the survey's interleave census (`MOSURA_DEBUG=recover`); the `ilv_orders` mark and `apply_ilv_orders` stay as a mark NOTHING SETS (the field is `Default` until the model-inverse variant fills it) -- said in the marks block, so it does not read as live -- R6 (3), executed |
| `MOSURA_ILV_DEBUG` | debug print gate (emit) | decompile/printc.rs:4360 | MIGRATED, R6 commit 2 -> `MOSURA_DEBUG=printc` -- done |
| `MOSURA_IMPLIED_DEBUG` | debug print gate | decompile/merge.rs:751 | MIGRATE in R6 commit 4 (its subsystem's topic), text verbatim after the old prefix -- R6 (4) |
| `MOSURA_INSTR_ALIAS` | debug print gate | decompile/pipeline.rs:132 | MIGRATE in R6 commit 4 (its subsystem's topic), text verbatim after the old prefix -- R6 (4) |
| `MOSURA_JT_DEBUG` | debug print gate | decompile/jumpbasic.rs:1107 decompile/jumpbasic.rs:1110 decompile/jumpbasic.rs:1120 decompile/jumpbasic.rs:1327 decompil | MIGRATE in R6 commit 4 (its subsystem's topic), text verbatim after the old prefix -- R6 (4) |
| `MOSURA_LOADGUARD` | debug print gate | decompile/heritage.rs:1108 | MIGRATE in R6 commit 4 (its subsystem's topic), text verbatim after the old prefix -- R6 (4) |
| `MOSURA_MERGE_WATCH` | debug print with a value | decompile/merge.rs:90 decompile/merge.rs:1319 decompile/merge.rs:1340 | DECIDE later (not emit): watches one varnode through the merge phases; a `debug::param` candidate -- listed |
| `MOSURA_MODIFY` | debug print gate | analysis/decompiler.rs:1157 | MIGRATE in R6 commit 4 (its subsystem's topic), text verbatim after the old prefix -- R6 (4) |
| `MOSURA_MONO` | debug print gate | decompile/recover.rs:1661 decompile/recover.rs:1664 | MIGRATE in R6 commit 4 (its subsystem's topic), text verbatim after the old prefix -- R6 (4) |
| `MOSURA_MSC16_EXE` | path | paths.rs:164 paths.rs:169 | paths.rs configuration, untouched |
| `MOSURA_OPACTION` | instrument | decompile/action.rs:14 decompile/action.rs:188 decompile/funcdata.rs:2536 decompile/funcdata.rs:2538 decompile/funcdata. | KEEP, documented: Ghidra's OPACTION_DEBUG selector (`Action::turnOnDebug`) -- attributes op mutations to actions -- listed |
| `MOSURA_PARAMDOUBLE_DEBUG` | debug print gate | decompile/pipeline.rs:991 | MIGRATE in R6 commit 4 (its subsystem's topic), text verbatim after the old prefix -- R6 (4) |
| `MOSURA_PERF` | debug print gate | decompile/action.rs:86 decompile/action.rs:102 decompile/action.rs:105 | MIGRATE in R6 commit 4 (its subsystem's topic), text verbatim after the old prefix -- R6 (4) |
| `MOSURA_PLACEHOLDER` | debug print gate | decompile/fspec.rs:1796 decompile/fspec.rs:1801 | MIGRATE in R6 commit 4 (its subsystem's topic), text verbatim after the old prefix -- R6 (4) |
| `MOSURA_PROTO` | debug print gate | decompile/fspec.rs:1676 decompile/fspec.rs:1679 | MIGRATE in R6 commit 4 (its subsystem's topic), text verbatim after the old prefix -- R6 (4) |
| `MOSURA_PROTO_PASS` | doc-only | decompile/recover.rs:1283 | a comment mentions it; no read -- drop the mention -- listed |
| `MOSURA_PTRFIT` | debug print gate | decompile/setcasts.rs:39 decompile/setcasts.rs:84 decompile/setcasts.rs:139 decompile/setcasts.rs:157 | MIGRATE in R6 commit 4 (its subsystem's topic), text verbatim after the old prefix -- R6 (4) |
| `MOSURA_RESTART_DEBUG` | debug print gate | analysis/decompiler.rs:198 decompile/heritage.rs:2513 decompile/heritage.rs:2638 | MIGRATE in R6 commit 4 (its subsystem's topic), text verbatim after the old prefix -- R6 (4) |
| `MOSURA_RETSPLIT` | behaviour knob (decompile) | decompile/blockjoin.rs:500 decompile/blockjoin.rs:503 | DECIDE later (not emit): `=0` disables ActionReturnSplit ("NOT a doctrine change") -- an A/B switch; same treatment as CALLEE_EFFECTS -- listed |
| `MOSURA_RETSPLIT_DEBUG` | debug print gate | decompile/blockjoin.rs:395 decompile/blockjoin.rs:499 decompile/blockjoin.rs:537 | MIGRATE in R6 commit 4 (its subsystem's topic), text verbatim after the old prefix -- R6 (4) |
| `MOSURA_RSDEBUG` | debug print gate | decompile/stackvars.rs:127 decompile/stackvars.rs:192 | MIGRATE in R6 commit 4 (its subsystem's topic), text verbatim after the old prefix -- R6 (4) |
| `MOSURA_SAVEDSLOT` | debug print gate | decompile/heritage.rs:1533 | MIGRATE in R6 commit 4 (its subsystem's topic), text verbatim after the old prefix -- R6 (4) |
| `MOSURA_SCAN_SHADOW` | debug print gate | analysis/decompiler.rs:1227 | MIGRATE in R6 commit 4 (its subsystem's topic), text verbatim after the old prefix -- R6 (4) |
| `MOSURA_SCHED_DEBUG` | debug print gate | recompile/watsched.rs:521 | MIGRATE in R6 commit 4 (its subsystem's topic), text verbatim after the old prefix -- R6 (4) |
| `MOSURA_SPARSE_DEBUG` | migrated |  | R6 commit 1 -> `MOSURA_DEBUG=sparse-switch` -- done |
| `MOSURA_SPFLOW_DEBUG` | debug print gate | decompile/stackvars.rs:478 decompile/stackvars.rs:556 | MIGRATE in R6 commit 4 (its subsystem's topic), text verbatim after the old prefix -- R6 (4) |
| `MOSURA_STACKARG` | debug print gate | decompile/heritage.rs:1459 decompile/heritage.rs:1462 | MIGRATE in R6 commit 4 (its subsystem's topic), text verbatim after the old prefix -- R6 (4) |
| `MOSURA_STACKARG_SHADOW` | debug print gate | analysis/decompiler.rs:478 | MIGRATE in R6 commit 4 (its subsystem's topic), text verbatim after the old prefix -- R6 (4) |
| `MOSURA_STMT_PC` | debug print gate (emit) | decompile/printc.rs:635 decompile/printc.rs:3442 decompile/printc.rs:3593 | MIGRATED, R6 commit 2 -> `MOSURA_DEBUG=printc` -- done |
| `MOSURA_STORE_DEBUG` | debug print gate (emit) | decompile/printc.rs:5043 | MIGRATED, R6 commit 2 -> `MOSURA_DEBUG=printc` -- done |
| `MOSURA_STRUCT` | debug print gate (emit) | decompile/structure.rs:575 decompile/structure.rs:578 decompile/structure.rs:650 decompile/structure.rs:851 decompile/st | MIGRATED, R6 commit 2 -> `MOSURA_DEBUG=structure` -- done |
| `MOSURA_STRUCTCOPY_DEBUG` | debug print gate (emit) | decompile/emit/arms/struct_copy.rs:51 decompile/emit/arms/struct_copy.rs:53 decompile/emit/arms/struct_copy.rs:58 decomp | MIGRATED, R6 commit 2 -> `MOSURA_DEBUG=struct-copy` -- done |
| `MOSURA_SUBVAR` | debug print gate | decompile/subvarflow.rs:1858 decompile/subvarflow.rs:1888 | MIGRATE in R6 commit 4 (its subsystem's topic), text verbatim after the old prefix -- R6 (4) |
| `MOSURA_SUMORD` | doc-only | decompile/emit/mod.rs:384 decompile/emit/arms/sum_order.rs:9 | history in docs (R2b commit 4 removed the read) -- listed |
| `MOSURA_SUMORD_CENSUS` | debug print gate (emit) | decompile/emit/arms/sum_order.rs:19 decompile/emit/arms/sum_order.rs:76 decompile/emit/arms/sum_order.rs:79 | MIGRATED, R6 commit 2 -> `MOSURA_DEBUG=sum-order` -- done |
| `MOSURA_SUMORD_CTX` | behaviour knob (emit) | decompile/emit/arms/sum_order.rs:19 decompile/emit/arms/sum_order.rs:80 decompile/emit/arms/sum_order.rs:82 | DELETE with its branch: `all` lifted the pointer-context gate for an A/B measured on zc26 (120 ptr vs 670 non-ptr chains) and lost; the default path is the landed behaviour, the census print stays under `sum-order` -- R6 (3), executed |
| `MOSURA_SWD_DEBUG` | debug print gate (emit) | decompile/structure.rs:3124 | MIGRATED, R6 commit 2 -> `MOSURA_DEBUG=structure` -- done |
| `MOSURA_SWITCH_DEBUG` | debug print gate (emit) | decompile/printc.rs:3044 | MIGRATED, R6 commit 2 -> `MOSURA_DEBUG=printc` -- done |
| `MOSURA_SWITCH_INDEX_UNRECOVERED` | text | decompile/printc.rs:2871 | a string in emitted-text diagnostics, not an env read -- listed |
| `MOSURA_TRACE` | instrument | decompile/action.rs:14 decompile/action.rs:79 decompile/funcdata.rs:2534 decompile/funcdata.rs:2543 decompile/funcdata.r | KEEP, documented: the rule-application trace (`scripts/trace-diff.sh`, `oracle/capture_trace`) -- the porting method's primary instrument, read once by `trace` -- listed |
| `MOSURA_TRACE_FUNC` | instrument | decompile/funcdata.rs:2562 decompile/funcdata.rs:2568 | KEEP, documented: scopes the trace to one function (the survey decompiles thousands) -- listed |
| `MOSURA_TYPEPROP` | debug print gate | decompile/infertypes.rs:692 decompile/infertypes.rs:714 | MIGRATE in R6 commit 4 (its subsystem's topic), text verbatim after the old prefix -- R6 (4) |
| `MOSURA_UJP_DEBUG` | debug print gate | decompile/pipeline.rs:1075 | MIGRATE in R6 commit 4 (its subsystem's topic), text verbatim after the old prefix -- R6 (4) |
| `MOSURA_UNRENDERED_` | text | decompile/printc.rs:2288 | a placeholder identifier prefix in the printer, not an env read -- listed |
| `MOSURA_VARARGS_DEBUG` | debug print gate | decompile/varargs.rs:48 decompile/varargs.rs:79 decompile/varargs.rs:194 | MIGRATE in R6 commit 4 (its subsystem's topic), text verbatim after the old prefix -- R6 (4) |
| `MOSURA_VARMAP` | debug print gate | decompile/varmap.rs:858 decompile/varmap.rs:862 decompile/varmap.rs:893 decompile/restrictlocal.rs:78 | MIGRATE in R6 commit 4 (its subsystem's topic), text verbatim after the old prefix -- R6 (4) |
| `MOSURA_WAR2_EXE` | path | paths.rs:158 paths.rs:161 | paths.rs configuration, untouched |
| `MOSURA_WATCH_CALL` | debug print with a value | decompile/funcdata.rs:2148 decompile/funcdata.rs:2149 decompile/funcdata.rs:2180 decompile/funcdata.rs:2182 | DECIDE later (not emit): watches one call's input edits; a `debug::param` candidate -- listed |
| `MOSURA_WATCOM_DIR` | path | paths.rs:186 paths.rs:190 | paths.rs configuration, untouched |
| `MOSURA_X32_EXE` | path | paths.rs:172 paths.rs:176 | paths.rs configuration, untouched |
| `MOSURA_X86_32_CSPEC` | test hook | analysis/overrides.rs:5 analysis/overrides.rs:50 analysis/overrides.rs:63 analysis/overrides.rs:111 analysis/loader/watc | KEEP, documented: the forced x86-32 cspec (`analysis::overrides`, loader/watcom.rs explains why it must exist) -- listed |
| `MOSURA_ZAP_DEBUG` | debug print gate | recompile/watsched.rs:644 | MIGRATE in R6 commit 4 (its subsystem's topic), text verbatim after the old prefix -- R6 (4) |
