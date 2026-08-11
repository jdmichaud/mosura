---
name: command-queue-modelled-as-change-channel
description: "Ghidra's analysisManager.disassemble()/createFunction() are COMMAND-QUEUE pushes that execute regardless of subscribers; mosura models them as change notifications, which silently drops them and causes the re-fire loop the thread-local dedupes paper over."
metadata: 
  node_type: memory
  type: project
  originSessionId: df001909-493d-4f50-92ac-53ef8ca6337d
  modified: 2026-08-11T06:16:09.338Z
---

**⭐ THE ROOT CAUSE of the listing hole — measured 2026-08-06, `fnpattern` + Ghidra source.**

`FunctionStartAnalyzer.java:835-859` raises **no change notification**. It calls, on the
**per-program singleton** manager (`:949`):

```java
analysisManager.disassemble(doNowDisassembly);      // -> schedule(new DisassembleCommand(...), :1128)
analysisManager.createFunction(funcResult, false);  // -> schedule(new CreateFunctionCmd(...),  :1132)
```

`schedule` (`:860`) pushes onto the **COMMAND QUEUE**. `codeDefined` (`:262-272`) is a *separate*
mechanism raised only when the listing actually changed — and Ghidra's own comment at `:385` flags
that disassembly deliberately does **not** go through change events.

**mosura models both commands as change-channel notifications** (`sched.code_defined` /
`sched.function_defined`). ⚠️ **A command executes regardless of subscribers; a notification reaches
only analyzers registered in that manager.** `analysis/mod.rs:246` builds a *second*
`AutoAnalysisManager` (`fs_mgr`) holding only the four `FunctionStartAnalyzer`s +
`PossibleDelayedFunctionCreator` — **no `Disassembler`, no `FunctionCreator`**. Measured on
`fnpattern`:

```
code_defined(08048120)   -> consumers=1, and it is "Function Start Search After Code". No disassembler.
function_defined(...)    -> consumers=0.   FunctionCreator, Constant Propagation, Decompiler Switch,
                                            External Jump Flow Override, Create Address Tables all miss it.
```

**One substitution produces BOTH known symptoms:**
1. **The listing hole** — the request evaporates. WAR2: **374 / 3018 functions (12.4%)** have an
   undisassembled body end; 6 corpus functions have the *entire* body undisassembled.
   `analyze()` is the single common driver, so `analyze_le_file` hits the identical hole.
2. **The infinite re-fire loop** — mosura fires `code_defined` on the **REQUEST**, Ghidra on the
   **RESULT**. Requesting disassembly at bytes that never decode re-notifies the Instruction-typed
   `AfterCode` analyzer forever. **So `SCHEDULED` and `PROPOSED` are accommodations for the wrong
   channel, not for any Ghidra behaviour — they dissolve when the channel is corrected.**

✅ **`SCHEDULED` (`function_start.rs:494`) is EXONERATED** — `08048120` was measured passing through
it, and its comment's claim ("converges without changing which addresses are ever requested") is
true as written. It was the lead hypothesis and it was wrong; don't re-suspect it.

`consumers=0` also means a pattern-discovered function's **callees are never discovered** — a
cascade, and the right shape to explain the 8 WAR2 addresses Ghidra finds and mosura misses.

**✅ LANDED 2026-08-10 @ `1a81975`:** `Scheduling` holds the real queue —
`BTreeMap<(priority, seq)>` FIFO-within-priority, Task/Disassemble/CreateFunction/OneShot
entries executing regardless of registration, active−2/−1 priorities, one-shots carrying their
instance. WAR2 LE SET-IDENTICAL 3023 (probe `examples/le_funcs.rs`); all suites green. The
two-manager split REMAINS (its ordering constraint stands).

**⚠️ 2026-08-10 SAME DAY: the queue was NOT the missing piece for #6/#3.** Five further
refutations on top of it (SR-in-fs_mgr, queued pattern creation, call-following, placeholder
refusal, unified executor) all fail — and Ghidra's own `CreateFunctionCmd` semantics
(source-verified) would create `1d74e` too, given mosura's state.

**⭐ RESOLVED BY ORACLE MEASUREMENT (`oracle/ghidra_scripts/LogFunctionEvents.java`, a
listener inside Ghidra's own war2 headless analysis):** `1d74e` is NEVER created; Ghidra
creates `1d7b5` at function event 177 and `1d76a` at 267 — different cascades, opposite order
to mosura's batch: SR scans `1d7b5` while `1d76a` does not exist (no entry to cross → no
verdict), and `1d76a`'s later real body shields `1d78c`. mosura batches them together only
because its main phase misses their callers (no call-following).

**⚠️ 2026-08-11 RETRACTION: the "context model" unblocker was a WRONG-IMAGE measurement.**
`bytesat` reads the LE view; the MZ bytes at `13a38` are `e8 1b 00` — the filed
inline-parameter thunk site, not 32-bit code. No context model is involved (no x86
`globalset`; the pspec defaults everything 16-bit). Zero `FUNCTION_REMOVED` refutes only
FUNCTION-removal — `ClearFlowAndRepairCmd` removes CODE UNITS. **THE CORRECTED UNBLOCKER
CHAIN: task #10 (no-return fall-through override + ClearFlowAndRepair repair) →
call-following → SR delivery.** Gotchas: state which IMAGE a byte read uses
(`mz_bytesat` vs `bytesat`); Ghidra holds domain-object listeners WEAKLY — root them in a
static field (measured: 0 events otherwise). Full ledger: `docs/analysis-open-tasks.md`.

**⛔ 2026-08-11 PARKED (user directive): the remaining #6/#3 links form a DEPENDENCY CYCLE**
— wave granularity ≡ U3 (patterns in-manager) → needs U2 (SR in-manager, PLT[0] ordering) →
needs cascade parity (spurious `128bc`) → needs call-following → needs wave granularity.
Each link individually measured red; landing is one ATOMIC multi-link change, not a
sequence. Reach classification proving no separate mechanism exists: of 7435 main-phase-
missing insns, 2 behind unfollowed edges, 91% rooted in byte-search-only discoveries
(`examples/mz_mainreach.rs`). Landed before parking: repair port `f23099d` (§9 #5 gate
green), detection `39bbdbe` (war2 misaligned 46→43), U1 `e24d92b`. Full ledger:
`docs/analysis-open-tasks.md`. The byte-exact lane does not depend on any of it.

Related: [[invention-inventory-empty]] (this is a NEW invention that inventory did not cover),
[[direction-retire-inventions-first]], [[hardcoded-x86-64-vs-cspec-class]].
