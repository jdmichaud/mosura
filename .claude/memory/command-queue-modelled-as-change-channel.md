---
name: command-queue-modelled-as-change-channel
description: "Ghidra's analysisManager.disassemble()/createFunction() are COMMAND-QUEUE pushes that execute regardless of subscribers; mosura models them as change notifications, which silently drops them and causes the re-fire loop the thread-local dedupes paper over."
metadata: 
  node_type: memory
  type: project
  originSessionId: df001909-493d-4f50-92ac-53ef8ca6337d
  modified: 2026-08-06T17:20:24.068Z
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

**Faithful target:** give `Scheduling` a command channel that executes regardless of subscribers,
matching `AutoAnalysisManager.schedule(cmd, priority)`. Step 1 (bounded): register `Disassembler` +
`FunctionCreator` in `fs_mgr`. Collapsing the two-manager split is the real retirement (Ghidra has
one manager per program) but `analysis/mod.rs:239-245` documents a real ordering constraint, so it
needs its own step.

Related: [[invention-inventory-empty]] (this is a NEW invention that inventory did not cover),
[[direction-retire-inventions-first]], [[hardcoded-x86-64-vs-cspec-class]].
