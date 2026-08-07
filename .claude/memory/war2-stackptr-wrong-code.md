---
name: war2-stackptr-wrong-code
description: The parked stack-pointer patch emits WRONG CODE (calls silently vanish) — a latent emission defect the 25 panics were masking; caught only by the call-count scan
metadata:
  type: project
---

**⛔ THE STACK-POINTER PATCH IS HELD — IT PRODUCES WRONG CODE (2026-07-28, agent war2-guard self-blocked).** `RuleIndirectCollapse` is CLEARED and lands alone.

**WHAT THE SCAN FOUND** (per-file line + real-call counts across all 1286, both sides state-asserted by marker before trusting): TOTAL LINES 63,680 → 41,912 (−34.2%, the intended spill-store removal) but **TOTAL CALLS 7,730 → 7,707 (−23 REAL CALLS DISAPPEARING)** — 5 files lose calls, 2 new constant-condition empty loops (baseline 0). `00106`/FUN_0001b8b8 5→1 calls (95→7 lines) · `00994`/FUN_00066da8 16→5 (70→9) · `00320`/FUN_0002fa30 9→3 · `00317`/FUN_0002f6f4 7→3 · `00110`/FUN_0001bd30 3→1. Whole body of FUN_0001b8b8: `void FUN_0001b8b8(void) { while (!SBORROW4(0,4)) { } return; }` — `SBORROW4(0,4)` is constant-false ⇒ **`while(true){}` replacing a 95-line body with 5 calls.** (~29 OTHER files lose lines while keeping call counts identical — that is the INTENDED win, separated so the −23 is neither dismissed nor over-read.)

**ATTRIBUTION (each state rebuilt and verified, not reasoned):** collapse+stackptr → WRONG · **collapse ONLY → CORRECT** (full 95-line body, all 5 calls) · **stackptr ONLY → WRONG** (identical empty loop). And **FUN_0001b8b8 is NOT in the 25-panic list**, proving the defect stands alone. ⇒ **the wrong code is the STACK-POINTER PATCH; `RuleIndirectCollapse` is CLEARED, not merely un-blamed.** (2 of the 5 — 0002f6f4, 0002fa30 — WERE panickers, so for those the collapse rule converts a panic into wrong code.)

**MECHANISM (measured):** the **CALL ops SURVIVE in the IR** (`dumpwar2 --raw` shows 4 CALL ops with and without the patch) but the emitted C omits them ⇒ **a STRUCTURING/EMISSION defect — a block losing its ops — NOT dead-code removal.** Same neighbourhood as the `ActionDoNothing`/block-removal code the original assert fired in ⇒ the panic and this were plausibly two faces of one upstream problem, and `RuleIndirectCollapse` fixed the face that asserted.

**⚠️⚠️ THE LESSON — THE PANICS WERE MASKING WRONG CODE.** Those functions never reached the survey, so the defect was invisible. **Fixing a crash EXPOSED a latent defect the crash was hiding.** And every headline looked like triumph: corpus byte-identical, panics 25→0, stale links 19,444→0, lines −34%. **ONLY THE CALL-COUNT SCAN DISAGREED.** ⇒ **RULE: run the per-file line + real-call scan on every emission-affecting change, AND whenever a fix converts failures into output** — not merely when emission changes are expected. (Lead condition 2 on the gate; it earned its keep in one shot.)

**SPACEBASE LEAK — NOT SMALL; lead withdrew "it should be small".** `pVar10` is the **ESP input varnode itself**, declared `spacebase *`, used as `*(uint1 *)(pVar10 + (iVar9 + -0x78))` — a **variably**-indexed frame access no fixed stack symbol can resolve. Ghidra never reaches this state: `printc.cc:3387` prints `BADSPACEBASE` as an explicit BUG MARKER, and Ghidra avoids it upstream by absorbing the variable index via `discoverIndexedStackPointers`/LoadGuard into an array symbol — **the subsystem documented as omitted at heritage.rs:1392 and varmap.rs:447. THIRD time that omission has surfaced as the true blocker** (see also [[war2-band-root-cause]]). Faithful fix = that subsystem. Reported rather than grown into the unit.

**BONUS GAP FOUND WHILE GROUNDING (held out, saved `scratchpad/typeop-spacebase-arm.patch`, file as its own small brick):** Ghidra's `TypeOpIntAdd::propagateAddIn2Out` trailing `isSpacebase` guard (typeop.cc:1247-1250) sits OUTSIDE the `command != 3` block and mosura lacks it entirely — a `TYPE_SPACEBASE` pointee has size 0, so an INT_MULT-scaled index returns command 3, skips `down_chain`, and relays the bare spacebase pointer. Ported + verified corpus-neutral, but it does NOT fix this leak (the agent had mis-identified which varnode carried the type), so it was held out rather than allowed to ride along. **Finding a real gap while grounding something else and NOT letting it ride is what keeps units attributable.**

**NEXT:** land `RuleIndirectCollapse` alone (approved, faithful, 25 panics→0, 19,444 stale links→0, case-B-clean). Then chase the emission defect from **FUN_0001bd30** (smallest, 3→1 calls, CALL ops confirmed present in the raw IR). LEAD HYPOTHESIS, explicitly labelled (lead's record on this bug is 1-for-5 — instrument first, follow the instrument not the lead): it may connect to the filed divergence that mosura INLINES `ActionUnreachable` into `ActionDeterminedBranch` where Ghidra has it STANDALONE at TWO slots (`:5490` base, `:5673`), so a block becoming unreachable by another route is never collected.

## ⚠️ MECHANISM CORRECTED (agent self-correction): the calls are DESTROYED, not unprinted

**The earlier "CALL ops survive in the IR ⇒ structuring/emission defect, not dead-code removal" was WRONG and would have sent the investigation to the wrong file.** `Funcdata::print_raw` (funcdata.rs:1118) iterates ALL ops with **no dead filter**, and a destroyed op has its output and inputs cleared, so it prints as a BARE OPCODE. The 4 bare `CALL` lines were **corpses, not survivors**. Measured correctly at the same op id: **without** the patch `0x1bdca:95: r0x0:4 = CALL r0x1ba38:4` (LIVE) · **with** it `0x1bdca:95: CALL` (DESTROYED). ⇒ **the calls really are being DELETED — dead-code/liveness territory, NOT printc.** Whole-function scale: **live ops 297 → 26 (~91% of FUN_0001b8b8 dies).**

**SECOND HYPOTHESIS ALSO CHECKED AND WRONG (before reporting it):** that `recover_stack`'s symbolic ESP tracking folded constants into a comparison. The constant-operand comparison `0x1ba14:57: r0x20b:1 = INT_SBORROW #0x0:4 #0x4:4` / `0x1ba17:66: CBRANCH ...` is present **IDENTICALLY WITHOUT the patch**. `SBORROW4(0,4)` is constant-false ⇒ the loop is `while(true)` in BOTH builds. **The patch does NOT create the degenerate branch.**

**ESTABLISHED, AND NOTHING BEYOND IT:** (1) the 5 call-losses + body collapse are caused by the **stack-pointer patch alone** (A/B/C matrix, each side rebuilt) — `RuleIndirectCollapse` CLEARED; (2) real, live CALL ops are **DESTROYED**; (3) the constant-condition CBRANCH making those blocks unreachable **PRE-EXISTS the patch**. ⇒ **SHAPE: a pre-existing degenerate branch was already there, and the patch removes whatever LIVENESS had been MASKING it; then the unreachable blocks — and the real calls inside them — get deleted. THE PATCH EXPOSES A LATENT DEFECT RATHER THAN INTRODUCING ONE.** The agent deliberately did NOT name the masking mechanism: two mechanism guesses had already fallen over on contact with measurement, so it has the **what** nailed and not the **why** — and said so. (Lead's own record on this bug: 1-for-5; no sixth hypothesis offered.)

**🔑 THE SUSPICIOUS THING IN ITS OWN RIGHT (agent's flag, lead's agreement): `INT_SBORROW #0x0:4 #0x4:4` — a comparison of TWO LITERAL CONSTANTS surviving to the output. A compiler does not emit a `cmp` of two literals**, so the constant operands may themselves be the upstream mosura defect that the stack pointer merely unmasks. NOTE THE IMPLICATION: if it pre-exists the patch, then **pre-patch mosura ALSO renders `while(true)` — just with the body still attached. Both builds may be wrong, differently.**

**➡️ LEAD-DIRECTED NEXT MOVE — ASK THE ORACLE, no hypothesis required.** `analyzeHeadless` is built at `/data/tools/ghidra_12.0.3_PUBLIC/build/dist/ghidra_12.0.3_DEV/support/analyzeHeadless` and WAR2 is a real binary Ghidra can load. Run it on **FUN_0001b8b8** and read what Ghidra produces: (a) **does Ghidra's IR also contain `INT_SBORROW` of two literal constants?** If NO ⇒ the constant operands are a mosura dataflow defect = the upstream bug both sides have been circling. (b) **Does Ghidra emit an infinite loop, or the 95-line body with its 5 calls?** That settles whether the pre-patch output was already wrong in a different way. This is CLAUDE.md's "ask Ghidra directly rather than chain source-reading guesses" — cheap, one headless run against an address we have pinned, and it either NAMES the upstream defect or eliminates a whole branch of the search.

## ✅ `RuleIndirectCollapse` LANDED `006fabc` — and the instrument NAMED the destroyer

Corpus 0.9535/57-60 (identical to the approved measurement; the stack patch verified a no-op on x86-64, not assumed), suite 564/0, clippy 0. Both inert arms carry an in-place **"INERT TODAY — DO NOT SIMPLIFY AWAY"** comment naming the missing producer + Ghidra site.

**THE DESTROYER, NAMED BY BACKTRACE (what five hypotheses could not do):**
```
KILLCALL op=OpId(95) @1bdca
   0: Funcdata::op_destroy
   1: ActionDeterminedBranch::apply
```
**`ActionDeterminedBranch` destroys the live CALL — ZERO times without the stack-pointer patch.** ⚠️ mosura INLINES `ActionUnreachable` into `ActionDeterminedBranch`, so the lead's filed divergence sits ON the named destroyer — **suggestive, NOT causal until shown; do not let it become hypothesis six.**

**THE CHAIN, MEASURED:** FUN_0001bd30 goes **61 → 13 live ops**. The CBRANCH at `0x1bdb9`, condition `INT_NOTEQUAL (LOAD of a stack slot), #0x0`, is present WITHOUT the patch and **GONE** with it. So stack recovery resolves that LOAD to a recovered stack varnode → the condition becomes constant → the branch becomes determined → the block holding the CALL is pruned. FUN_0001b8b8 is the same shape at **297 → 26**.

**AGENT STOPPED ONE STEP SHORT ON PURPOSE — and was right to.** The deciding question: **is that branch GENUINELY determined?** If the slot only ever holds 0, Ghidra would prune it too ⇒ correct dead-code removal that merely LOOKS alarming ⇒ **the patch is EXONERATED**. If the LOAD is being wrongly forwarded across a redefinition ⇒ real wrong code. **The raw IR CANNOT answer it**: two different LOADs both print as `u0x17200` (one off the stack, one off `r0x18 + 0x60` — a linked-list `next`) and `print_raw` shows NO SSA VERSION, so "which load feeds the compare" is unreadable there. Recognising the evidence can't settle it, and saying so instead of producing a third confident mechanism, was the right call.

## ➡️ THE DECISIVE CHECK (lead-directed): THREE-WAY, with the ORIGINAL BYTES as tiebreak

1. **THE ORIGINAL BYTES — the real authority** (per [[goal-is-the-binary-not-ghidra]]). Disassemble `FUN_0001bd30` around the CBRANCH at `0x1bdb9`: **what writes the stack slot that LOAD reads, between the write and the compare — and can it ever be non-zero?** The manifest already carries each function's original bytes, so this is cheap. Slot genuinely only ever 0 ⇒ branch really determined ⇒ pruning CORRECT ⇒ **patch exonerated** (real binaries do contain unreachable error paths). A live value written before the compare ⇒ mosura forwards a LOAD across a redefinition ⇒ **real wrong code, localized**.
2. **Ghidra via analyzeHeadless** (`/data/tools/ghidra_12.0.3_PUBLIC/build/dist/ghidra_12.0.3_DEV/support/`) on `FUN_0001bd30` + `FUN_0001b8b8` — corroboration; does Ghidra prune the same calls? Ghidra keeping them + bytes saying the slot can be non-zero = two independent sources agreeing mosura is wrong.

Neither outcome needs a hypothesis from anyone.

## 📌 TWO STANDING-RECORD ITEMS ACCEPTED
1. **The call-count scan belongs on ANY change that converts failures into output** — not just emission-shaped ones. The panics were masking wrong code, so the old trigger was too narrow.
2. **⚠️ THE WAR2 RE-MEASURE NUMBERS ARE INVALID** — they came from a build emitting wrong code on 5 functions. RELOC_EXACT 0→2, the 48-63% bucket, p99 25→30, the whole band shape: **all must be RE-TAKEN once this is settled.** Discard the flattering number rather than carry it.

Artifacts: three falsified hypotheses recorded do-not-retry (with the **bare-opcode/`print_raw`-has-no-dead-filter trap** called out explicitly so the next agent doesn't repeat it); baseline 1286-file emitted-C snapshot saved so the call-count scan is cheap to re-run.
