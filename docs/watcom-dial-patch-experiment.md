# The Watcom dial-patch experiment — handoff

**Status:** proposed, not started. This document is a complete brief for an agent picking
up the experiment cold. Read it end to end before touching anything. It is written to be
self-contained, but it links the existing documents you MUST also read rather than
recopying them.

**Author's note (Fable, 2026-08-22):** I wrote this after a day of source-shape levers on
the WAR2 byte-exactness corpus netted +6 EXACT and +0.0004 WGSS and then hit the same wall
three separate ways. Every one of those walls was the *compiler's* tie-breaking, not our
emitted C. This experiment is the one remaining move with a large possible outcome, and I
cannot run it myself (it is binary patching of a compiler executable). Do not treat my
framing as gospel — but do read the "hard-won lessons" section before you form your own,
because most of them are mistakes already made once here at real cost.

---

## 0. The one-paragraph version

WAR2.EXE was built with a Watcom 10.0-line C compiler whose **code-generator dials are set
differently from the shipped 10.0a** we compile with (an "interim build" — routine in that
era; no such build survives publicly). We reproduce 764/2797 functions byte-exactly; the
residue is dominated by **register-allocation tie-breaks** and **instruction-scheduling
order** that are the *compiler's* choices, unreachable by changing our C. The experiment:
locate those dials in 10.0a's own `wcc386.exe` (OW 1.0 source names them; mosura disassembles
the binary), patch a **copy** of the compiler toward WAR2's observed behavior, recompile the
corpus, and measure. A patch that moves EXACT by tens of functions **confirms** the ceiling is
compiler identity and converts the rest of the campaign into a finite list of dials. A patch
that moves nothing **refutes** it and sends the work back to our side. Either result is worth
more than another week of source-shape levers.

---

## 1. Why this experiment, and why now

The campaign has three kinds of residue:
1. **Recoverable source-shape differences** — our C differs from what the original source
   must have been. These are landable and mostly harvested (see the git log: sum-order,
   aggregation, param-order, volatile, stack-args, jump-table families all landed here).
2. **Correctly-refused differences** — cases where matching the bytes would require emitting
   wrong or non-Ghidra C. These stay MISMATCH by design.
3. **Compiler identity** — the original's compiler made a different *codegen* choice (which
   register, which schedule) that no legal C of ours changes. **This is now the dominant
   remaining mass**, and it is what this experiment attacks.

Three independent probes on 2026-08-22 all bottomed out in (3):
- **Arg-setup order** (`MOV EAX,var; MOV EDX,const` vs our constant-first): no pragma order,
  argument permutation, nested-vs-hoisted call form, or compiler version (10.6) moves it.
  The scheduler places the pair; five of six sites in one function follow 10.0a's rule and
  the sixth doesn't.
- **Statement interleave**: the original's instruction order is the *scheduler's* output, not
  the source's statement order, and the scheduler doesn't round-trip its own output.
- **Register role swaps** (e.g. EAX↔EDX): the allocator picks the other register on a tie our
  byte evidence cannot see, because array-source vs adjacent-scalars-source compile identically
  when the allocation happens to agree.

All three point at the **same two dials**: the allocator's conflict/register-list order and
the scheduler's priority. Both are DATA or small code in `wcc386.exe`. Both are already
located in principle (§4). The prerequisite reconnaissance is done; what remains is the surgery
and the measurement, which needs a fresh agent.

**The honest prior:** I put this at maybe 40% to move EXACT by ≥30, 35% to move it by <10
(dial is real but entangled/symmetric, like the fold turned out to be), 25% to move nothing
(residue is ours or the dial isn't where we think). Even the negative outcomes are decisive —
they retire the interim-build hypothesis, which has shaped every family session for months.

---

## 2. REQUIRED READING (do not skip; this doc does not recopy them)

In this order:

1. **`docs/watcom-nofold-patch.md`** — the WORKED EXAMPLE of exactly this method, start to
   finish, on a different dial (the LEA fold). It contains: how the site was located from OW
   source, why the first signature search failed and what fixed it (the compiler lowers a
   sparse switch as a binary-search tree, not a `CMP` sequence — *instrument the tool doing the
   measuring*), the exact byte patch, the sha256 pre/post, the idempotent patch script that
   refuses to run against unexpected bytes, the separate object cache discipline, and — most
   important — **the construct-validity error that invalidated the first conclusion**. Your
   experiment is this one with different dials. Copy its structure.

2. **`docs/war2-toolchain-synthesis.md`** — the interim-build hypothesis and its four legs
   (LEA fold [reclassified], `DoubleRegs[]` allocation order, callee-save policy, load
   scheduling). The "OW 1.0 source reconnaissance" section names the dials and their source
   locations. **Read the `DoubleRegs` subsection carefully: the naive version of THIS
   experiment was already cancelled once**, on evidence, before patching — the substitutions
   are near-symmetric (EAX→EDX 689 vs EDX→EAX 675) and the class is 99.7% entangled (only ~9
   functions have regalloc as their sole divergence). That does NOT kill the experiment, but it
   tells you the naive "reorder the table and count rows" version is dead. §6 explains what to
   do instead.

3. **`docs/byte-exact-families.md`** — the F2 family and its **falsifiable prediction**,
   recorded before this experiment runs: *if the interim build's difference is
   result-register-assignment preference, patching the allocation dial toward WAR2's preference
   should move F2's rows TOGETHER WITH the regalloc MOV>MOV class. If regalloc moves and F2
   doesn't (or vice versa), the unification is wrong.* This is your pre-registered check — hold
   yourself to it.

4. **`docs/watcom-codegen-fingerprint.md`** and **`docs/watcom-10.0-beta-codegen.md`** — every
   Watcom revision (7.0 … 10.0-beta … 10.0a … 10.6 … 11.0 … OW2) has been compiled and
   fingerprinted; none matches WAR2 exactly. This is why the answer is "interim build," not
   "some other shipped version." Don't re-litigate version identity; it's settled.

5. **`docs/war2-recompile-remeasure.md`** — the canonical measurement runbook. Every trap in §7
   below traces to a lesson recorded here or in the memory files.

**Memory files** (`/home/jd/.claude/projects/-home-jd-projects-mosura/memory/`, indexed in
`MEMORY.md`): `war2-compiler-identity.md` (pile-B is a LIST OF CLAIMS, not a verdict; the fold
member flip-flopped twice — re-check each claim's evidence, and beware over-correcting in
either direction), `allocator-model-thread.md` (the full 2026-08-22 allocator investigation:
what the OW allocator actually does, which levers landed, which were refuted and why),
`volatile-recovery-and-scheduler.md` (the scheduler MODEL we already have — `recompile::watsched`
— faithful to OW `inssched.c`; it PREDICTS 10.0a's behavior and disagrees with WAR2's on the
holdout functions, which is itself evidence a dial differs), `experiment-discipline.md`
(census-before-code, WGSS-first landing bar, pre-register ceilings), `bisect-checkout-discipline.md`.

---

## 3. The environment (exact paths)

- **Repo:** `/home/jd/projects/mosura/mosura` (note the doubled path; the outer
  `/home/jd/projects/mosura` is an sshfs mount, the repo is one level in). NOT a git repo at
  the outer level; `git` works inside the inner dir.
- **Reference compiler (NEVER WRITE TO THIS):**
  `/home/jd/projects/warcraft2-re/tmp/watcom-experiments/watcom_10.0a/WATCOM`. The compiler
  executable is `BINB/WCC386.EXE` (541,364 bytes, an LX / DOS-extender image — "MS-DOS
  executable, LX for OS/2, Intel i386"). It runs under dosemu via `BIN/W32RUN.EXE`
  (W32RUN-hosted; W32RUN must be on the DOS PATH).
- **The subject:** `/home/jd/WAR2.EXE`.
- **Corpus manifest + recovered C:** produced by `war2_survey` into `/data/be2/zcNN/`
  (manifest.tsv, recovered/NNNNN.c, prelude.h). The current baseline tree is `zc26`
  (764 EXACT / WGSS 0.4801). Column 9 of the manifest is the original function's bytes (hex).
- **Compile cache:** `/data/be2/cache`. **Content-and-toolchain-id keyed.** The patched
  compiler does NOT change the toolchain id, so a patched run sharing this cache would be
  silently served STOCK objects. **Use a separate cache** (`/data/be2/cache-dialpatch` or
  similar) for every patched-compiler run. This is the single most important operational rule
  in the whole experiment — the fold experiment nearly reported stock numbers as patched ones.
- **Builds:** always `CARGO_TARGET_DIR=/data/mosura-target` (per-invocation env, never persists;
  forgetting it builds into the sshfs `target/` and runs a stale binary — first symptom is
  "my instrument print is missing"). `/data` fills up; prune old `/data/be2/zcNN` trees but
  keep `cache/`, the last ~3 trees, and ALL `*-rec.tsv` (the measurement record).
- **OW 1.0 source:** `/data/tools/watcom/open_watcom_1.0.0-src.zip` — the oldest OW source in
  existence, the reference for every dial's decision procedure.
- **dosemu staging:** `scripts/setup-watcom-dosemu.sh <ver> [--compile x.c]` stages a compiler
  into `~/.dosemu/drive_c/WAT<ver>`. For flagged compiles write your own BAT (the script
  compiles flagless); the recipe is in the script and reproduced in the allocator-model memory.
  10.6 stages cleanly; 10.5's DOS binary is damaged media (use 10.6 — they're codegen-identical).

---

## 4. The two dials, with source anchors

Both are read out of `open_watcom_1.0.0-src.zip`. OW 1.0 is NOT 10.0a, but the decision
procedures are structurally the same and the fold experiment confirmed the source reads
transfer to the 10.0a binary. Confirm each against the binary before trusting it.

### Dial A — the register allocation order (`386rgtbl.c`, `DoubleRegs[]`)

- **Source:** `bld/cg/intel/386/c/386rgtbl.c`. `DoubleRegs[] = { EAX, EDX, ECX, EBX, ESI, EDI,
  EBP, ESP }` is the register list a 4-byte temp draws from, in preference order. `ParmSets`,
  `ByteRegs`, `WordRegs`, `ABCDRegs` are the sibling lists.
- **How it's consumed:** `bld/cg/c/regalloc.c` — `AssignConflicts` sorts conflicts by savings
  (`regsave.c` `CalcSavings`, loop-depth weighted), then `GiveBestReg` walks the tree's register
  list IN TABLE ORDER, scoring each by `CountRegMoves`, taking the strict-max, and **breaking
  ties by preferring a register already in `GivenRegisters`, else the first in table order**.
  The conflict list itself is built by PREPEND (`conflict.c:61`) so equal-savings ties resolve
  in reverse IR-encounter order. Read `allocator-model-thread.md` for the full trace — it's
  already extracted.
- **In the binary:** the register-list tables are byte sequences of `hw_reg_set` masks. Locate
  by the mask constants and the surrounding `RegSets[]` / `ClassSets[]` dispatch. The masks'
  encoding is in `bld/cg/intel/h/` (hw_reg_set layout).
- **What to patch, and what NOT to:** DO NOT just reorder `DoubleRegs` and count rows — that
  version was cancelled on evidence (§2 item 2: symmetric substitutions, 99.7% entanglement).
  The row count measures the CASCADE, not the dial. Instead: (a) form a HYPOTHESIS about the
  actual tie-break difference from the *strict regalloc-only* specimens (functions whose ONLY
  divergence class is regalloc — there are ~6, all SAME_SHAPE, so a correct dial converts them
  cleanly with no confound), (b) patch toward that, (c) predict which specimens should flip and
  by the F2 prediction (§2 item 3) which other class should co-move, (d) measure against the
  prediction, not against the raw row count.
- **Crucial distinction — table-order vs tie-order.** The `DoubleRegs` cancellation used the
  near-symmetric substitution counts (EAX→EDX 689 ≈ EDX→EAX 675) to refute a **table-preference**
  dial, and that reasoning is correct: a fixed list-order preference biases substitutions one way.
  But the same symmetry does NOT refute a **tie-order** dial — reversing which of two equal-savings
  temps is processed FIRST swaps *both* their roles in the same function, producing symmetric
  counts by construction. So the live Dial-A hypothesis is not "the register list is ordered
  differently" (refuted) but "the conflict-list processing order or the equal-savings tie-break is
  different" (the `conflict.c:61` prepend order, or `GiveBestReg`'s `GivenRegisters`-reuse tie-break).
  Do not let the old symmetry argument talk you out of the tie-order version — it only kills the
  table-order version.

### Dial B — the instruction scheduler priority (`inssched.c`)

- **Source:** `bld/cg/c/inssched.c`. `ScheduleIns` is a bottom-up list scheduler:
  minimum `StallCost` first, then greatest height (`AnnointADag`), then greatest `InsStallable`,
  then latest source id (ties preserve source order). `InsStallable` (inssched.c:101) weights
  operands by class: `N_INDEXED +3, N_REGISTER +2, N_MEMORY +1`. The per-CPU operand-stall
  values are in `bld/cg/intel/386/c/386funit.c`.
- **We already have a faithful MODEL of this:** `crates/mosura/src/recompile/watsched.rs`,
  documented against these exact source lines. It PREDICTS 10.0a's schedule and reproduces it
  on most functions; it disagrees with WAR2's order on a small set of holdouts (e.g. the arg-setup
  6th site, FUN_00019344, FUN_00073328). **Those holdouts are your Dial-B specimens** — they are
  where WAR2's scheduler priority differs from 10.0a's. `dumpsched` (gitignored, in
  `crates/mosura/examples/`) prints model-prediction vs original per window; use it to see the
  disagreement before patching.
- **In the binary:** the priority comparison in `ScheduleIns` and the `InsStallable` operand
  weights. The operand weights (2/1/3) are the most likely single-dial difference — if WAR2
  weights a register operand differently, the arg-setup pair (`MOV reg,reg` vs `MOV reg,const`)
  reorders. Locate `ScheduleIns` via its `StallCost`/height/`InsStallable` structure; the
  operand-class constants are small immediates.

### Which dial first

Dial A (allocation). Rationale: it has the cleanest specimen set (the ~6 regalloc-only
SAME_SHAPE functions — no cascade confound), it carries the pre-registered F2 co-move
prediction so a positive result is double-confirmed, and the fold experiment already proved
the locate-and-patch method on a `wcc386.exe` code site. Dial B (scheduler) is second because
its specimens are all multi-class (entangled) and its effect is harder to isolate — but we
already have the model to tell us exactly which functions and windows to watch.

---

## 5. The method (from the worked example, generalized)

1. **Source first.** Read the decision procedure in OW 1.0 source until you can state it as a
   predicate. Don't hypothesize the binary before you understand the source.
2. **Ask the compiler how it lowers itself.** Don't assume the C construct's machine shape —
   compile the *shape* with 10.0a (`examples/dumpwc`) and look. The fold search failed because
   the author assumed a `CMP` sequence and Watcom emitted a binary-search tree. Instrument the
   measuring tool.
3. **Search the binary with the REAL shape**, then **disassemble with mosura**
   (`examples/dumpraw <file> <hexoffset> <len> [hexbase]` — mosura reading its own toolchain,
   dogfood). Corroborate the site against an INDEPENDENT signal (the fold site was confirmed by
   a neighboring arm whose behavior we'd already measured black-box).
4. **Patch a COPY.** Never write the reference tree. Prefer neutralizing dispatch edges to
   NOP (`0x90`) over editing arm bodies (displacements). Write an **idempotent Python patch
   script that asserts the pre-image bytes** and refuses on mismatch; record sha256 before and
   after. Copy the whole `WATCOM` tree to scratch, patch the copy's `BINB/WCC386.EXE`.
5. **Validate the patch in isolation BEFORE any corpus run.** Compile a battery of small probes
   (`dumpwc` against the patched compiler — point it at the copy with `DUMPWC_WATCOM=<copy>/WATCOM`)
   proving: the targeted transform changed to the intended shape, and the NEIGHBORING transforms
   are byte-identical to stock. A patch with collateral damage is worse than no patch — you'll
   misread the corpus delta. Sanity check on determinism (guaranteed post-commit d45c4ed): two
   compiles of the SAME source tree with the SAME compiler must produce `cmp`-identical objects;
   any difference between two compiles of the same tree with DIFFERENT compilers is therefore the
   compiler, which is the signal you want.
6. **Corpus run with a SEPARATE cache** (`--cache /data/be2/cache-dialpatch`). Emit is already
   done (reuse the zc26 recovered tree — the C doesn't change, only the compiler does), so this
   is `recompile_check` only, pointed at the patched WATCOM dir and the separate cache.
7. **Measure against the PREDICTION, not the raw count.** `scripts/war2-verdicts.sh
   <baseline-rec.tsv> <patched-rec.tsv>` for flips + WGSS movement. Check the pre-registered
   specimens flipped and the F2 co-move prediction held. Report EXACT and WGSS together, always.

---

## 6. What "success" and "failure" each mean (interpretation discipline)

This is where the fold experiment went wrong the first time, so read it twice.

- **A wholesale toggle tests a strawman.** Turning a transform fully OFF tests "WAR2 NEVER does
  it" — but WAR2 both does and doesn't (it folds 336 sites AND declines to fold at the F2 rows).
  A dial that can only be all-on or all-off can match NEITHER mixed state. If your patch is a
  wholesale disable, the only sound conclusion available is an INVARIANCE result (does the class
  move at all?), not a directional one. Prefer a patch that changes the *condition/order*, not
  one that disables the feature.
- **Row counts measure symptoms, not causes.** 13,583 regalloc divergence rows do NOT mean
  13,583 fixable defects — one upstream tie-flip cascades into every downstream assignment. The
  strict single-class specimens (regalloc-only, SAME_SHAPE) are the only clean measurement; a
  dial is confirmed by converting THOSE, and the cascade (if the dial is real) then unwinds
  additional multi-class functions as a bonus you observe, not as your primary metric.
- **Near-symmetric substitution kills a table-order hypothesis but NOT a tie-order one.** If
  EAX→EDX and EDX→EAX occur in comparable numbers, a table REORDER cannot be the cause (it would
  bias one way) — but a tie-ORDER reversal produces symmetry BY CONSTRUCTION (it swaps both roles
  in one function; see §4 Dial A "table-order vs tie-order"). So the symmetry refutes only the
  `DoubleRegs`-reorder version; it says nothing about a conflict-processing-order or equal-savings
  tie-break dial, which is the version actually worth patching. This exact confusion cancelled the
  dial once; don't let it cancel the right hypothesis too.
- **Pre-register the ceiling and the specimens.** Before the corpus run, write down: which
  named functions you predict flip, how many EXACT you'd call a success, and the F2 co-move
  prediction. Then measure. A result you can reinterpret freely after seeing it proves nothing.
- **A null result is a real result.** If the best-justified patch moves nothing, that is strong
  evidence the residue is NOT this dial — either it's ours after all, or the interim build
  differs elsewhere. Report it plainly; do not keep tuning the patch until something moves
  (that's overfitting to noise). One well-justified patch, measured once, per dial.
- **Beware over-correction.** The fold claim flip-flopped twice (never-folds → folds-normally →
  unresolved → compiler-identity). Each flip was an over-correction from a single new data
  point. When your result surprises you, add evidence before reversing a conclusion.

---

## 7. Operational traps (each cost a wasted round here at least once)

- **Wrong WATCOM dir** → dosemu prints `Bad command or file name - WCC386` for every
  cache-missing unit, recorded as COMPILE_FAIL **and cached** (content-keyed, doesn't age out).
  Recovery: delete the poisoned cache entries by their fresh `.log` files and re-run.
- **Shared cache across compilers** → silently serves stock objects for a patched run. Separate
  cache, always (§3).
- **Missing `CARGO_TARGET_DIR=/data/mosura-target`** → edits "have no effect" (stale binary
  runs). If an instrument print is missing, `ls -la` both binaries' mtimes first.
- **`recover` is a LITERAL string**, not a flags file. `recompile_check <exe> <manifest>
  <recovered-dir> recover <WATCOM-dir> --cache <cache> --out <tsv>`. Passing a flags file
  compiles every unit with wrong per-function flags and fakes a wholesale regression.
- **Per-function flags come from the prologue** (`buildconfig::watcom_10_0a` / `detect`): base
  `-5r -fpi87 -s -onatx`, plus `-d1+` where the function has a frame, `-4r` (not `-5r`) where an
  in-place scaled LEA proves pre-Pentium tuning. The dial patch does not change flags; keep them
  as `recover` derives them.
- **The `-dirty` param-order cache is git-stamp-keyed**; every uncommitted state shares one
  stamp. A run with a broken binary poisons `param-orders.<sha>-dirty.tsv` for later runs.
  Delete it after any suspect run. (Not directly relevant to a compile-only patched run, but if
  you re-emit, watch for it.)
- **If verdicts shift wildly, diff the emitted SOURCES first** (`cmp` loop vs the baseline
  tree). Byte-identical sources + shifted verdicts = the harness/compiler invocation changed,
  not the code. For a dial-patch run the sources ARE identical by construction (same recovered
  tree), so ANY verdict shift is the compiler — which is exactly the signal you want, but verify
  the sources really are identical so you know the shift is the patch and nothing else.
- **`war2_survey` and `recompile_check` are slow** (~100s analyze + ~100s emit for survey; a
  full recompile is minutes cache-warm, much longer cache-cold — and a patched run is cache-cold
  by construction). Background anything over ~2 min. Never run cargo in the foreground while a
  background cargo may hold the target-dir lock.
- **Run-to-run pragma jitter is FIXED as of commit d45c4ed** (the per-callee pragma merge was a
  HashMap draw). If you see a few functions' pragmas differ between byte-identical rounds, that's
  a regression in the merge, not model noise — but you shouldn't, post-d45c4ed.

---

## 8. Validation specimens (know these before you measure)

- **Dial A (allocation) clean specimens** — functions whose ONLY divergence class is regalloc,
  all SAME_SHAPE, no cascade confound. Regenerate the current list from the divergence table:
  `recompile_check … --divergences <tsv>` on the zc26 tree, then filter for rows where the
  function's entire class set is `regalloc` (± `layout-shift`). As of the 2026-08-22 census
  there were ~6 such functions (~38 rows, ~38 lost-weight). These are your pass/fail set: a
  correct Dial-A patch converts these to EXACT with zero collateral regressions.
- **The role-swap family** — FUN_00045aa4 (converted to EXACT via aggregation already, so it's
  a control now), FUN_0005fb24 (ESI↔EDI on near-tied derived pointers), FUN_0006a720
  (ESI↔EDI), FUN_00025f50 (EBX↔ECX). If Dial A is right, the still-MISMATCH ones here move.
- **F2 family** (`byte-exact-families.md`): the pre-registered co-move check. F2's rows should
  move together with the regalloc class under a correct Dial-A patch.
- **Dial B (scheduler) specimens** — the watsched model's holdouts: FUN_00073328 (the `[EBP+8]`/
  `[EBP+0xc]` load pair no source shape moves), FUN_00019344 (window order even faithful cost
  hand-computation can't reproduce), FUN_0004b750's 6th call site. `dumpsched` shows the
  model-vs-original disagreement per window.
- **Neighbor-invariance probes** (patch validation, §5.5): small `dumpwc` programs exercising
  the transforms ADJACENT to your dial, which must stay byte-identical to stock.

---

## 9. Deliverable

Write your conclusion as a new section at the end of THIS document (or a sibling
`docs/watcom-dial-patch-results.md` linked from here), containing, per dial attempted:
the source predicate, the located binary site (offset + disassembly + independent
corroboration), the exact patch (offsets, before/after bytes, sha256 pre/post, idempotent
script), the isolation-validation battery result, the corpus delta (EXACT and WGSS, baseline
→ patched, via `war2-verdicts.sh`), whether the pre-registered specimens and the F2 co-move
prediction held, and the interpretation under §6's discipline. If a dial moved nothing, say so
plainly and state what that rules out. Update `war2-compiler-identity.md` memory with the
outcome (it is a list of claims — mark each as confirmed/refuted with the evidence).

**Do not** change the shipped harness to use a patched compiler. The patched compiler is an
INSTRUMENT for testing the hypothesis, exactly as the no-fold patch is. Byte-exactness is
defined against stock 10.0a; a dial patch that "wins" only tells us WHERE the residue lives, it
does not become the build.

---

## 10. If you get stuck

- The method has a complete worked example in `watcom-nofold-patch.md` — when in doubt, mirror
  its structure step for step.
- The allocator and scheduler are both already modeled in Rust (`watsched.rs`, and the OW-source
  trace in `allocator-model-thread.md` memory) — you do not need to re-derive how they work,
  only find them in the binary and change them.
- `dumpwc`, `dumpraw`, `dumpdis`, `dumpsched`, `dumpobj` (all in `crates/mosura/examples/`,
  gitignored `dump*` family) are the instruments: compile-a-snippet, disassemble-raw-bytes,
  disassemble-a-manifest-function, scheduler-model-vs-original, disassemble-an-OMF-public.
- The single highest-leverage habit from this whole campaign: **instrument first, hypothesize
  second, and never trust a row count as a cause.** Every multi-day dead end here came from
  believing a symptom count was a mechanism.

Good luck. — Fable
