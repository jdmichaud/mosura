---
name: war2-missing-calls-class
description: RETRACTED HEADLINE — the real figure is 94.8% of Ghidra's calls, 92 of 1286 functions dropping 246 calls; the 41%/455 number came from a linear-sweep reference
metadata:
  type: project
---

**🔴 THE CAMPAIGN'S MOST IMPORTANT MEASUREMENT (2026-07-28, agent war2-guard).**

**mosura emits ~41% of the binary's call instructions. 455 of 1286 WAR2 functions drop calls — in MASTER, right now, IDENTICALLY with and without the stack-pointer patch.**

| | count |
|---|---|
| ORIGINAL call instructions | **8,953** (objdump linear sweep = an UPPER BOUND: it decodes padding/data as instructions; 32 functions emit MORE than it, which is the honest noise indicator) |
| emitted, baseline | **3,705 (41.4%)** |
| emitted, +stack-pointer patch | **3,693 (41.2%)** |
| functions emitting fewer calls than the original | **455 of 1286 — identical in both builds** |
| moved by the entire stack-pointer patch | **12 calls** |

**⚠️⚠️ WHY IT WAS INVISIBLE FOR THE WHOLE CAMPAIGN — AND THE RULE THAT FOLLOWS.** Every wrong-code scan the lead specified was **DIFFERENTIAL** (unit vs baseline). A differential gauge can only see *incremental* loss, so **a defect present on BOTH sides is structurally invisible to it.** The lead insisted on the scan (right) and specified it against the wrong reference (wrong) — while the user's framing had already said the target is the binary. **NEW STANDING RULE: MEASURE AGAINST THE ORIGINAL BINARY, NOT AGAINST THE PREVIOUS BUILD. Differential scans are for ATTRIBUTION ("did this change cause it") and are WORTHLESS FOR DETECTION.** See [[goal-is-the-binary-not-ghidra]].
(Also corrected: the earlier 7,730→7,707 scan counted `extern` DECLARATION lines as call sites — direction held, magnitude inflated.)

**THE BYTES SETTLED THE STACK-PATCH FORK — and the answer was neither option the lead posed.** `FUN_0001bd30` original x86-32: `1bd41 xor edx,edx` / `1bd43 mov [ebp-0xc],edx` (slot := 0, prologue) … **`1bdaa mov [ebp-0xc],esi` ← LOOP-CARRIED WRITE OF A LIVE VALUE** / `1bdad mov esi,[esi+0x60]` / `1bdb2 jne 1bd56` (back-edge) / `1bdb4 mov ebx,[ebp-0xc]` (the LOAD) / `1bdb9 je 1bdda` (THE BRANCH) / `1bdca call 0x1ba38` (the "lost" call). **The slot is NOT always 0 ⇒ the branch is genuinely conditional ⇒ the call is reachable ⇒ pruning it IS wrong code ⇒ the patch is NOT exonerated.** Frame mapping confirmed independently on four slots (4 pushes + `mov ebp,esp` ⇒ `[ebp-0xc]` = entryESP−0x1c = the IR's `INT_ADD r0x10,#0xffffffe4`). mosura forwards a pre-loop constant across a loop-carried redefinition.
**BUT THE PATCH IS ALSO NOT THE CAUSE:** in BASELINE IR the three loop-body calls (`0x1bd6d`, `0x1bd85`, `0x1bd94`) are **ALREADY dead**; baseline emits **1 of 4 real calls**, the whole loop body replaced by `iRam... = iVar5;`. The loop-carried store `0x1bdaa` is dead in BOTH builds. **The patch takes the function from 3-of-4 dropped to 4-of-4 — it WIDENS a pre-existing class, it does not create it.**

**LEAD DECISION ON THE PATCH: still HELD, but DEMOTED — and explicitly NOT on a "wrong code already exists" argument** (that proves too much and must not enter our precedents). The real reason: **the patch's 12 lost calls and the 455-function class are plausibly the SAME mechanism** (a load forwarded across a redefinition, then a branch wrongly determined). If so, fixing the class fixes the patch's regression too and **both land clean together**. If the class fix does NOT subsume it, revisit the block with the class fixed and the 12 in real context.

## ➡️ THE TASK NOW, AHEAD OF EVERYTHING: why is `FUN_0001bd30`'s loop body destroyed in BASELINE mosura?

Three loop-body CALLs and both conditional-block stores dead with **no patch applied**, across **455 functions**. `ActionDeterminedBranch` is the named destroyer for the TAIL call (backtrace-proven) and the first place to instrument — but the agent explicitly does **NOT** assert it is the same mechanism for the loop body. Instrument that separately.

**RUN analyzeHeadless — for the CLASS, not the fork** (`/data/tools/ghidra_12.0.3_PUBLIC/build/dist/ghidra_12.0.3_DEV/support/`). The bytes already settled the fork, so Ghidra would be mere corroboration there. For the 455-class it is decisive in a different way: **does Ghidra keep that loop body?** Ghidra KEEPS it ⇒ mosura has a specific named defect to hunt. Ghidra DROPS it too ⇒ we have something **wrong against the BINARY while faithful to Ghidra** — still a defect we own under [[goal-is-the-binary-not-ghidra]], but a very different kind, and it would reshape what "faithful port" buys at the top of the funnel.

**The WAR2 band re-measure is invalid for a SECOND reason now: both sides of that comparison drop calls.** See [[war2-stackptr-wrong-code]].

## ⭐ GHIDRA VERDICT: **MIS-PORT** — and a per-function WAR2 oracle unlocked (2026-07-28)

**THE LOADER PROBLEM SOLVED — the campaign's biggest capability unlock.** Ghidra loads only the MZ stub of a DOS/4GW LE ([[war2-dos4gw-le]]), so headless on the `.EXE` cannot see protected-mode code at all — which is why **Ghidra has never been usable as an oracle on WAR2 for this entire campaign**. SIDESTEP: import just the function's own bytes as a RAW BINARY based at its own VA — `BinaryLoader` + `x86:LE:32:default` + a `DecompileAt.java` postScript. **Any WAR2 function is now one command from its Ghidra rendering.**

**`FUN_0001bd30`, Ghidra:**
```c
for (iVar4 = _DAT_0008f20c; iVar4 != 0; iVar4 = *(int *)(iVar4 + 0x60)) {
  if (... (iVar3 = func_0x0001bc90(), iVar3 == 0)) && (iVar3 = func_0x0001ba38(1), iVar3 != 0)) {
    uVar2 = func_0x0001ec50();
    if ((uVar2 < 0xb) && (uVar2 < uVar1)) { iStack_1c = iVar4; uVar1 = uVar2; }
  }
}
if ((iStack_1c != 0) && (iVar4 = func_0x0001ba38(1), iVar4 != 0)) { return 1; }
```
**All 4 calls · the full loop body · `iStack_1c` modelled as a REAL STACK LOCAL with its LOOP-CARRIED definition `iStack_1c = iVar4;` preserved and correctly tested afterwards** — exactly the write whose mosura counterpart (`0x1bdaa mov [ebp-0xc],esi`) is dead in BOTH builds. mosura emits **1 of 4** calls (baseline) / **0 of 4** (with patch). `FUN_0001b8b8`: same story — Ghidra produces nested loops and 3+ calls where mosura emits `while (!SBORROW4(0,4)) { }`.

**MOSURA CANNOT PLEAD MISSING CONTEXT:** this was a **179-byte raw import with unresolved call targets and no surrounding functions**, and Ghidra still nailed it. ⇒ **decompiler logic, not analysis context.** The 455-function class is a genuine MIS-PORT against BOTH authorities (the binary AND Ghidra) — the good fork of the two: a specific named defect to hunt, not a "faithful to Ghidra but wrong against the binary" dilemma.

**⚠️ FLAGGED WITHOUT ASSERTING (agent declined to make it hypothesis six):** `mosura-analysis/docs/decompiler-bug-d4-tailcall-empty-loop.md` documents this EXACT symptom ("empty infinite loop with the call dropped"), classified MIS-PORT, and **D4 is recorded as LANDED** — yet the symptom is live with a DIFFERENT trigger (D4 = cross-function tail-`jmp`; `FUN_0001bd30` ends in a normal `ret`). Same symptom FAMILY, not demonstrably the same mechanism. **Either D4's fix is incomplete, or two mechanisms produce one symptom.** With `OPACTION_DEBUG` in place this is a single query, not a probe — designated the FIRST USE of the new facility.

**LEAD DIRECTION — fold the oracle into task #4 as PERMANENT TOOLING, not a recorded recipe** (a recipe is something someone must remember = the exact failure mode the user told us to stop repeating): script it (`scripts/ghidra-decompile-at.sh <va>`); **ADD A BATCH MODE** so mosura can be diffed against Ghidra **per-function across all 1286** — that finds defect CLASSES wholesale instead of one function at a time, and given how much of this campaign went into hunting single functions, **a standing mosura-vs-Ghidra sweep over WAR2 may be worth more than any individual fix**; and put the loader caveat in the script header so nobody later "fixes" it back to loading the `.EXE`.

## ✅ FACILITY BUILT (`75782b5` + `7ec7d4a`) — and it NAMED THE DESTROYER on first use, no ad-hoc probe

Both corpus byte-identical, suite 565/0, clippy 0. **The user's "build the axe" directive paid off immediately.**

**`print_raw`'s two traps fixed with GHIDRA'S OWN RENDERERS (not an invented format):** destroyed ops (whose inputs/output `op_destroy` clears) were printing as bare opcodes indistinguishable from a live STORE/BRANCH — now routed through `op_str` = Ghidra `PcodeOp::printDebug` so a **corpse prints `**`** (pinned by a new test so the trap can't return); and no SSA version meant two LOADs both printed `u0x17200:4` — now Ghidra `Varnode::printRaw`: `(i)` input, `(<seqnum>)` naming the **defining op**, `(free)`. `ir_parity` reads only the address prefix, so unaffected.

**`OPACTION_DEBUG` ported — and the crux is the RULE/ACTION split:** mosura already had the *rule* half (`MOSURA_TRACE`), and **a rule trace can only ever see the op the rule was applied to, never an action destroying some OTHER op.** That blind spot is exactly what every backtrace probe this campaign was working around. Implementation: `debug_mod_check` at the nine mutation primitives mosura has (Ghidra has twelve), `debug_mod_print` at each action boundary via `ActionGroup::apply`, bracketed as Ghidra's `Action::perform` does; selection follows `turnOnDebug(name)` — `--debug opaction` for all, or a single action name. Off, it costs one bool per mutation.

**⭐ ACCEPTANCE MET — `FUN_0001bd30`, BASELINE, NO PATCHES, via `--debug opaction` + a `before ≠ ** → after = **` filter:**
```
determinedbranch KILLED 0x1bd6d:188  was: CALL r0x1bc90:4(free)
determinedbranch KILLED 0x1bd85:224  was: CALL r0x1ba38:4(free)
determinedbranch KILLED 0x1bd94:248  was: CALL r0x1ec50:4(free)
determinedbranch KILLED 0x1bda7:280  was: STORE ... r0x0:4(free)
determinedbranch KILLED 0x1bdaa:283  was: STORE ... r0x18:4(0x1bdb0:...)
```
**`ActionDeterminedBranch` destroys the ENTIRE loop body — all three real calls AND both conditional-block stores, including the loop-carried `0x1bdaa` write — in MASTER, TODAY, with no stack-pointer patch.** Same action that destroyed the tail call with the patch applied. The lead's filed `ActionUnreachable`-inlining divergence now sits on a **measured** destroyer rather than a suspected one — **but knowing WHICH action deletes is NOT knowing WHY it decided to; neither lead nor agent is promoting it to a cause.**

**TWO FREE FINDINGS from the facility:** the earlier `oppool`/`deadcode` kills are of the **call-guard INDIRECT markers, not the calls** — which explains the ordering that misled the investigation earlier; and the new `(free)` marker shows the destroyed STOREs' **pointer varnode is FREE, i.e. not in the SSA tree at all** — abnormal for a STORE pointer and possibly its own thread (flagged as an OBSERVATION TO CHECK, explicitly **not** a hypothesis to pursue).

## ➡️ LEAD SEQUENCE: absolute gauge FIRST, then the aimed hunt

**(1) Finish the absolute-vs-original gauge as a standing harness report** (prototype `scratchpad/abscall2.py`; document its two counting traps IN the report — `extern` lines and the own-definition line both match a naive call regex). **It goes first because it is the SUCCESS METRIC for the hunt**: fix `ActionDeterminedBranch` without it and you have a fix with no verdict — and this campaign has twice mistaken a differential improvement for a real one. **(2) Defer `BLOCKCONSISTENT_DEBUG`** as filed. **(3) THEN THE HUNT, with the question now aimed: NOT *who* deletes, but *WHY IT DECIDED TO*.** Ghidra's `ActionDeterminedBranch::apply` acts only when `cbranch->getIn(1)->isConstant()` — so in mosura **that condition varnode IS a constant. WHAT MADE IT CONSTANT?** That is the upstream defect, and it is the same shape as the `INT_SBORROW #0x0:4 #0x4:4` flagged earlier — a comparison of two literals no compiler emits. With the facility in place, "which action or rule set that varnode constant" should be a QUERY, not a probe; **if it isn't, that gap is the signal to EXTEND the facility rather than hand-roll.**

## ⛔⛔ RETRACTION (2026-07-28, agent war2-guard, self-corrected within one turn)

**THE "41% / 455 FUNCTIONS / ~5,000 MISSING CALLS" HEADLINE ABOVE IS WRONG. DO NOT PLAN AROUND IT.**

It came from counting `call` mnemonics in an **objdump LINEAR SWEEP** of each function's bytes (8,953). A linear sweep decodes padding and inline data as instructions, so it wildly overstates the true count. It was labelled an upper bound and then quoted as a headline anyway.

**CORRECTED, against Ghidra's own per-function output for all 1286:**
| | count |
|---|---|
| GHIDRA emits | **3,909** calls |
| mosura emits | **3,705** = **94.8% of Ghidra** |
| functions where mosura emits fewer than Ghidra | **92 of 1286** |
| calls missing | **246** |
| worst | `0003dd60` Ghidra 31 → mosura **0** · `0006af2c` 18→1 · `00051298` 12→2 |

Cross-checked against the one hand-verified function: `FUN_0001bd30` reads Ghidra 4 / mosura 1, matching the disassembly exactly.

**⚠️ THIRD COUNTING-PREDICATE FAILURE THIS SESSION — all the same shape: a filter that looked obviously right and quietly matched more than intended.** (1) `extern` declaration lines counted as call sites; (2) the "skip the function's own definition line" filter **allowed leading whitespace**, so it silently ate every *indented* line containing a `FUN_xxxx()` call — it had Ghidra emitting 1 call for a function that emits 4; (3) the linear sweep. **FIXES: require column 0 AND the function's own name. RULE: always keep one function whose true answer you know INDEPENDENTLY (hand-verified from the disassembly) — it caught two of the three.**

**⚠️ REFERENCE HIERARCHY — Ghidra-as-reference has the SAME BLINDNESS ONE LEVEL UP.** Ghidra's per-function output is the best PRACTICAL reference and a huge improvement on a linear sweep, but it is a **PROXY, not ground truth: a call that BOTH tools drop is invisible to it** — the differential-blindness failure moved up a level. **THE HIERARCHY IS: bytes > Ghidra > mosura.** Ghidra's output is the standing gauge (cheap, now available for all 1286); the AUTHORITY remains the original machine code obtained by a **FLOW-FOLLOWING disassembly from the function entry** — never a linear sweep, which was the actual defect in the 8,953. Verify specific functions against the real disassembly as tiebreak. **Never read "94.8% of Ghidra" as "94.8% of the binary."**

**WHAT THE CORRECTION CHANGES:** the class is REAL but **~5× smaller** — 92 functions, not 455. The agent WITHDREW its own proportionality argument for reconsidering the stack-pointer block (12 lost calls against 246 is ~5% = a real widening, not noise); **the lead's stated reason for demoting the patch stands on its own and is the better one** — the 12 and the class are plausibly the same mechanism, so fixing the class fixes both. **AND THE REFRAME IS GOOD NEWS: 94.8% of Ghidra with the defect concentrated in 92 functions is a far better position than the campaign believed** — a tractable work queue, not a systemic collapse.

## 🛠️ THE PER-FUNCTION GHIDRA ORACLE, AT FULL SCALE (built, not yet committed)

`scripts/ghidra-decompile-war2.sh` (named VAs · `--file` · `--all`) + `oracle/ghidra_scripts/DecompileFunctions.java`. **The batch builds ONE sparse image with every function at its own VA, so the whole sweep is a SINGLE JVM start rather than 1286 — all 1286 functions decompiled, 0 errors, in one run.** Loader caveat in the script header IN CAPITALS so nobody "fixes" it back to importing the `.EXE` ([[war2-dos4gw-le]]). This sweep produced the corrected numbers and is the wholesale-class-finding capability the lead asked for. **Work queue: `scratchpad/fewer-calls-vas.txt` = the 92 VAs, worst-first. First target `0003dd60` (Ghidra 31 → mosura 0) — a function where we emit NOTHING will have an unambiguous cause.** Landing plan: fold the absolute gauge onto Ghidra's output (not the retracted sweep), then commit the tooling as one piece.
