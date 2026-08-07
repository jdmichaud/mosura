---
name: war2-subregister-heritage-rootcause
description: "ROOT CAUSE of the 92-function dropped-call class — a wide register read binds past an intervening sub-register write (AL write ignored by EAX read); foundation-menu item A, now a measured wrong-code defect"
metadata: 
  node_type: memory
  type: project
  originSessionId: 99103a08-9d06-430b-8446-4ca5e3757106
  modified: 2026-07-29T10:20:46.000Z
---

**🎯 ROOT CAUSE FOUND (2026-07-28, agent war2-guard) — entirely BY QUERY, no new probe.** The facility built the turn before ([[war2-missing-calls-class]]) paid for itself: two queries (`MOSURA_OPACTION=1` then `MOSURA_TRACE=1`) walked from a deleted call to a sub-register heritage defect.

**THE DEFECT — a 4-byte read binds to a stale def, ignoring an intervening 1-byte write to the same register:**
```
0x1bd56:139  r0x0:4(0x1bd56:139) = INT_XOR r0x0:4 r0x0:4    ; eax = 0          (xor eax,eax)
0x1bd58:148  r0x0:1(0x1bd58:148) = COPY u0x17000:1          ; al  = [esi+0x1f] (mov al,...)
0x1bd5b:149  u0x66100:4          = COPY r0x0:4(0x1bd56:139) ; cmp eax,0x5c  ← binds to the XOR, IGNORES the AL write
```
**Everything downstream is then CORRECT BEHAVIOUR ON A WRONG PREMISE**, and the trace shows each step: `earlyremoval` destroys the AL write (no readers — because the wide read never referenced it) → `equal2zero` rewrites the compare substituting constant `0` → `constfold` makes ZF constant → `propagatecopy` carries it to the CBRANCH → `determinedbranch` sees a constant condition and correctly deletes a loop body that is genuinely unreachable *under that premise* — three real calls and both conditional stores.

**⇒ `ActionDeterminedBranch` is the EXECUTIONER, NOT THE CULPRIT.** Neither lead nor agent promoted it to a cause, which was right. **And the lead's filed `ActionUnreachable`-inlining divergence is NOT implicated — retiring the lead's last standing hypothesis on this bug (six for six wrong; treat lead leads as hypotheses only).**

**WHY: mosura heritages each exact `(space, offset, size)` as its OWN SSA location**, so `r0x0:1` and `r0x0:4` are separate variables unless width-normalization unifies them. **`normalize_write_size` IS implemented (heritage.rs:712) — but its driver `normalize_ranges` is scoped to WIDENING RE-ENTRY ONLY and is documented in-file as "a dormant no-op today"**; first-pass normalization is left to pass-0 batch heuristics that don't cover this shape.

## ⭐ THE REFRAME: foundation-menu item A has CHANGED CATEGORY

**It was filed as a FOUNDATION INVESTMENT** — an abstract faithfulness improvement competing with other abstract improvements, correctly held for a user decision. **It is now a MEASURED WRONG-CODE DEFECT: 92 functions, 246 dropped calls, every one of which Ghidra renders correctly.** Wrong code is the campaign's hardest rule and is disqualifying ⇒ **this is a DEFECT FIX, not an investment choice, and it falls inside the user's standing directive to build what byte-exactness needs. LEAD RULING: AUTHORIZED — no separate investment decision required.** (Agent's own framing: it "now comes with a price tag attached instead of a shrug.")

**It is also a plausible single explanation for the stack-pointer patch's 12 lost calls** — same shape, a read resolving to a stale definition and a branch then wrongly determined. If so, **fixing A subsumes the patch's regression**, which is exactly why the patch was demoted rather than landed on a "wrong code already exists" argument ([[war2-stackptr-wrong-code]]).

## ➡️ SCOPE IT BEFORE BUILDING — order matters

1. **SWEEP THE 92 FIRST** (`scratchpad/deficits.txt`, worst-first; `0003dd60` = Ghidra 31 → mosura **0**, the loudest specimen). **Does the class share this mechanism or split?** One cause across 92 is a very different fix from three causes across 92 — know before planning, not mid-build. This is precisely the wholesale-class-finding the batch Ghidra oracle was built for.
2. **THE SCOPING QUESTION THAT MAY SHRINK THIS DRAMATICALLY: is the fix DRIVING THE EXISTING `normalize_write_size` ON THE FIRST PASS (a brick), or does it genuinely need the full coarse-SSA foundation (a campaign)?** Ground against Ghidra's actual `normalizeWriteSize`/`Heritage` behaviour — what Ghidra does on the FIRST heritage pass for a sub-register write under a wider read. **That answer is the difference between days and weeks.**
3. **Then plan-first → lead gate → build**, with the absolute gauge as the success metric: **3,705 / 3,909 is the number to move**, and it is now a standing report (`scripts/war2-absolute-gauge.py`, `2a9825a`, metric registry + both counting traps documented in-script) rather than something to remember to run.

## ✅ STEP 1 DONE — CLASS CONFIRMED, AND THE TRIGGER IS A **COMPILER IDIOM** (2026-07-29)

Worst specimen `0003dd60` (Ghidra **31** calls → mosura **0**) has the identical chain, **verified by trace not inferred**: `u0x66100:4 = COPY r0x0:4(0x3dd67:21)` → `COPY #0x0:4` — the 4-byte read binds to `xor eax,eax` and ignores the `mov al,[ebx+0x802c8]` between them → `equal2zero` → `constfold` → constant CBRANCH → the whole **0x2b2-byte body** deleted.

**WHY THE CLASS IS LARGE: Watcom's zero-extended byte load `xor r32,r32 ; mov r8,[mem] ; cmp r32,imm ; jcc`**, repeated per field tested (in `0003dd60`: 0x802c8/0x80248/0x80258/0x80278) — and the FIRST one skips everything. Population over raw bytes: **47/92 deficit fns (51%) vs 119/1194 controls (10%) = 5× enrichment**; agent correctly called it a LOWER bound and refused to round it up to "the" explanation (~45 unmatched).

**LEAD DIRECTION — REPLACE THE BYTE PREDICATE WITH AN IR PREDICATE.** Raw bytes test a *proxy* ("does the idiom appear literally"); **the mechanism itself is exact and directly visible in IR: a read binding to a def that is followed, before the read, by a NARROWER WRITE to an OVERLAPPING location.** Idiom-agnostic, spelling-agnostic, and evaluable with the debug facility. Expect most of the 45 to light up. Any that still don't = a genuinely SEPARATE cause, to be **named separately, never folded in**. (Sanity-check the predicate against a known-legitimate case first — a large count here is exactly the shape that fooled us twice, see [[measurement-determinism-first]] §fourth class.)

## ✅ STEP 1b + STEP 2 ANSWERED (2026-07-29) — ONE CAUSE, AND IT'S A **BRICK**

**IT IS ONE CAUSE, NOT THREE.** Swept with the facility, not by hand: `MOSURA_OPACTION=determinedbranch` over the whole program in ONE 8-minute run, attributing every CALL destruction to its owning function → fns where determinedbranch destroyed ≥1 CALL: **93**; of those inside the 92-fn deficit set: **86 = 93.5% of the class**; unexplained deficits: **6**; CALL ops destroyed: **231** (vs 246 missing call *sites* — different denominators, reconcile when reporting; that gap is where a 7th cause would hide). **⇒ plan for ONE fix; the 6 are a separate tail, filed separately, NOT absorbed.** (The IR/action-level predicate replaced the raw-byte proxy exactly as directed — 51%→93.5%.)

**⭐ IT IS A BRICK, NOT A CAMPAIGN — AND THE DEFECT IS *THE GATE*.** mosura computes `widened` as `globaldisjoint.merged_range(..)` → `Some(prior) if size > prior`; **on pass 0 there IS no prior entry ⇒ `widened` is empty ⇒ `normalize_ranges` returns early ⇒ FIRST-PASS NORMALIZATION NEVER HAPPENS AT ALL** ("a dormant no-op today" — the file said so). `normalize_write_size`/`normalize_read_size`/the driver are **already built**. Ghidra's `guard()` has NO widening gate (heritage.cc:1164-1182). **The widening gate is an ADAPTATION ⇒ never grandfathered ⇒ deleting it is not even a port decision, it's cleanup.** This confirmed the lead's grounding hypothesis below.

**PLAN (approved, GO through B5 — no second gate):** B1 remove the widening gate, keeping the *faithful* refinement carve-out `size>4 && max_write<size` (heritage.cc:2610) · B2 retire in the SAME change the pass-0 adaptations it collides with (`normalize_read_size`'s single-write-width hack, `refine_overlaps`' register-only Normalize mode) or risk double-normalizing — **but capture B1-alone numbers in passing for attribution** · B3 hand-verified specimens FIRST, before any corpus run (`FUN_0001bd30` 4 calls, `FUN_0003dd60` 31) — **if AL doesn't merge into EAX the premise is wrong ⇒ STOP, don't repair forward** · B4/B5 gauge + gated fixture moves.

**⚖️ LEAD'S GATING RULING (reusable):** a faithful port / adaptation-deletion **LANDS**; the corpus gets no veto; the gate separates *mis-port* from *correct-port-that-moves-fixtures*. **THE ONLY BLOCKER IS WRONG CODE ⇒ run the absolute call gauge as a BLOCKING check, not a success metric.** Land iff 3705/3909 rises AND no function loses a call it currently emits; if any function loses calls, STOP even if every other number improves. **That asymmetry is the entire lesson of [[war2-stackptr-wrong-code]]** (byte-identical corpus + 0 panics + −34% lines all read as triumph; only the call-count scan caught it). **AGENT'S FLAGGED RISK:** mosura runs `normalize_ranges` BEFORE candidate gathering rather than inside `guard()`, so pass 0 exercises a never-executed path — **if it bites, fix TOWARD `guard()`'s structure; do NOT reintroduce a condition to work around it.** If it lands clean, immediately re-test the held stack-pointer patch on top — this plausibly subsumes its 12-call regression.

## ⛔ B1 BUILT → **FALSIFIER FIRED. NOT A BRICK — CAMPAIGN.** Reverted, master clean (2026-07-29)

**PREMISE CONFIRMED THOUGH: `FUN_0001bd30` RECOVERED ALL 4 CALLS** (`func_0x0001bc90`, `func_0x0001ec50`, `func_0x0001ba38`×2) — matching Ghidra AND the original's four call instructions. **The prize is real and reachable.**

**THE GATE HAD TWO LEVELS, and the second only showed up by BUILDING:** removing the inner `widened` set changed nothing (zero PIECE ops, byte-identical). The real gate is `heritage.rs:1616` — `if widens { remove_revisited_markers(..); normalize_ranges(..); }` ⇒ **`normalize_ranges` was never even CALLED on pass 0.**

**B1 ALONE IS WRONG CODE ON EVERY BLOCKING CHECK:** corpus 0.9535→0.9273, 57→55/60; **`pointerrel` 0.966→0.463 with its loop body GONE (`for(...){ }`) — OUR OWN DEFECT SHAPE appearing in the corpus**; `packstructaccess` 0.966→0.485; **DECOMPILE_FAIL regression (≥11 WAR2 fns panicking mid-emit, baseline 0)**; and `0003dd60` did NOT recover (0 calls, 0 PIECE) ⇒ **normalization fires UNEVENLY = the tell the implementation isn't general.** ⇒ **the pass-0 batch heuristics ARE load-bearing**, and B2 would remove *more* of that support (agent's double-normalization argument: right about direction, wrong about sequencing — self-named). **Agent STOPPED rather than special-casing the broken spaces** — it could see that path and refused it, because inventing a gate to make the path behave is how the original adaptation got there. Patch preserved `scratchpad/B1-widening-gate-removal.patch`.

### ⭐ LEAD RULING: CAMPAIGN AUTHORIZED — AND IT IS **BOUNDED**: port `Heritage::placeMultiequals` (heritage.cc:2599-2645)
Not escalated to the user: standing directive is never stop, and [[finish-parked-before-new]] forbids parking a deep problem for an easier win — with a confirmed prize this is not walk-away-able.

**The source promotes the agent's "lead" to THE ANSWER. `placeMultiequals` is ONE LOOP OVER THE DISJOINT TASK LIST**, per range: `collect(range,read,write,input,remove)` (:2609) → `if (size>4 && max<size) refinement + re-collect` (:2610-2616, **the carve-out the agent correctly kept**) → `if(!removevars.empty()) removeRevisitedMarkers` (:2626-2627) → `guardInput` + **`guard()` — where normalize fires** (:2628-2629) → `calcMultiequals` + insert MULTIEQUALs (:2630-2642).

**⇒ mosura's `normalize_ranges` as a GLOBAL PRE-PASS before candidate gathering STRUCTURALLY CANNOT FIRE UNIFORMLY — it has no per-range read/write sets to normalize against.** That single fact explains ALL THREE measured symptoms at once: `0003dd60` not normalizing, the `remove_revisited_markers` interaction, and the stack-frame breakage.

**⇒ THE CAMPAIGN = port that loop's SHAPE and let normalization fall out of `guard()` where Ghidra puts it. A faithful port of ONE bounded function, NOT an open-ended foundation. SEQUENCE: structure FIRST, then the pass-0 heuristics retire BECAUSE NOTHING CALLS THEM ANY MORE — never removed-then-coverage-reconstructed. That ordering dissolves the B2 sequencing problem.** No plan-gate needed while it's a faithful port of that function; only non-port work is gated.

**NON-NEGOTIABLES:** no invented gate to make a path behave (a broken space means the STRUCTURE is still wrong) · 3705/3909 must RISE and no fn may lose a call it currently emits · **any empty-loop render is WRONG CODE, never a fixture move to gate.** ⚠️ **RE-RUN THE EMIT FIRST — `war2-survey/src/` was regenerated by the partial broken build; `scratchpad/src-baseline/` is the good snapshot** (stale-tree false measurement is our costliest recurring class, [[measurement-determinism-first]]).

## 🏅 THE CONJUNCTION IS DIAGNOSTIC, NEITHER ARM IS — with a **legitimacy control** (2026-07-29)

Best measurement work of the arc. Agent bracketed the class with TWO independent IR predicates and **controlled the second before anyone could quote it**:
- **A** = `determinedbranch` destroyed ≥1 CALL. **B** = a CBRANCH condition folded varnode→constant in the rule pool.
- **B alone OVER-CLAIMS: 217 fns program-wide fold; 129 of them lose NO calls, and Ghidra independently agrees "Removing unreachable block" on ≥24. Constant-folding a branch is NOT inherently a defect — B has a HIGH BASE RATE.**
- On the 92: **both = 86**; exactly one = 2 (`0006af2c`, `00068902`); **neither = 4** (`00051298`, `00079130`, `000198d4`, `0006529f` — filed separately in `scratchpad/tail-separate-cause.txt`; `00051298` = Ghidra 12 → mosura 2, a real deficit with a DIFFERENT cause, worth its own investigation AFTER this lands).

**⇒ RULE FOR THE REST OF THE CAMPAIGN: measure your predicate's BASE RATE on a control population before quoting its hit rate.** A predicate firing on 217 fns and diagnostic on none alone is exactly the [[measurement-determinism-first]] fourth-class trap; this didn't just avoid it, it *measured the trap's size*.

**Lead ruling on the missing exact measurement:** the lead's literal predicate (a read binding past a narrower overlapping write) is a **heritage-time** property the facility can't yet dump per-function at scale; agent verified it by trace on 2 specimens and bracketed with A∧B instead, and asked rather than hand-rolling. **Correct to ask; answer = NO, don't build the extension first — THE FIX IS THE CHEAPER MEASUREMENT.** If 86 fns recover calls the population is proven post hoc, exactly and for free; building a dump to predict a number the build hands us in hours is precision we don't need for a decision already made. Filed as a facility item, off the critical path.

## 🔎 LEAD'S GHIDRA GROUNDING FOR STEP 2 (read done 2026-07-29, cited — points NARROW)

**In Ghidra, width normalization is NOT a special case — it IS the guard, run on every range on every pass.** `Heritage::guard` (heritage.cc:1156), called for every disjoint-task-list range at heritage.cc:2629, has only this:
```
for read:  if (vn->getSize() < size) *iter = vn = normalizeReadSize (vn,op,addr,size);   // heritage.cc:1172-1173
for write: if (vn->getSize() < size) *iter = vn = normalizeWriteSize(vn,   addr,size);   // heritage.cc:1179-1180
```
**No widening-re-entry condition exists anywhere near it.** And `size` is the UNIONED range formed on the FIRST pass: `LocationMap::add` (heritage.cc:33-70) erases every overlapping element and reinserts one range spanning them (:49-65) ⇒ `r0x0:1` and `r0x0:4` are ONE size-4 range from the start; the AL write is rewritten into a 4-byte write built by PIECE from the prior EAX value, so the later EAX read **cannot** bind past it. Exactly the binding our specimen gets wrong.

**⇒ mosura already has all three pieces** — `LocationMap` + union (heritage.rs:37-61, its doc comment already cites heritage.cc:33), `normalize_read_size` (:265), `normalize_write_size` (:712). **What differs is the WIRING: our pass-0 runs batch heuristics the file itself calls a "hack" (:437, :1263) and reserves real normalization for widening re-entry, where Ghidra runs it uniformly.** If that holds the fix is STRUCTURAL, not architectural, and **the "coarse-SSA foundation" framing is an artifact of OUR OWN dormant-driver comment, not a property of Ghidra's design** — a good instance of [[faithful-type-of-wrong-ir]]'s "instrument/ground, don't infer from our own code's self-description".

**Falsifiers (stated up front, this is a hypothesis-with-citations, not a verdict):** the pass-0 batch heuristics turn out load-bearing for something normalizeWriteSize doesn't cover, or our `collect`/range formation never reaches `guard` with the unioned size. Either ⇒ genuinely a campaign ⇒ report, don't start.

**TASK #4 COMPLETE:** both `print_raw` traps fixed, `OPACTION_DEBUG` ported, the per-function Ghidra oracle (all 1286, one JVM start, 0 errors) and the absolute gauge landed; `BLOCKCONSISTENT_DEBUG` deferred as filed.
