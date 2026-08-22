# Declaration order and IR-generation order — handoff

Follow-on to [`watcom-dial-patch-results.md`](watcom-dial-patch-results.md) (your results) and
[`watcom-dial-patch-experiment.md`](watcom-dial-patch-experiment.md) (the original brief). Same
discipline as that brief: pre-register before measuring, one well-justified change per question,
report EXACT and WGSS together, never land a fitted-to-oracle result. Work in this worktree on
`dial-patch`; nothing here touches master until JD merges.

**Baseline moved: master is now zc27 = 764 EXACT / WGSS 0.4801 on a DETERMINISTIC emitter**
(`d45c4ed` fixed the pragma-merge jitter; `b5898d7` fixed a second leak in the kernel gate's
`spec_view`; a full double-emit now yields 0 differing TUs). Merge master into this branch before
any measurement — your `/data/wt-dialpatch-target` binary predates both fixes and a round run on it
carries the old random draw in ~2 TUs. The recovered tree to compare against is
`/data/be2/zc27/recovered` with `/data/be2/zc27-rec.tsv` (zc26 is byte-identical except one TU).

Two items, in order. Both came out of your own results; both are on our side of the fence.

---

## Item 1 — the declaration-order axis, built as a model-inverse

### What is established (your §3)

Swapping only the local declaration order converts `FUN_000464b4`, `FUN_0005fb24`,
`FUN_0001798c` to EXACT under stock 10.0a. Ceiling over every permutation: 3 of 12 on
SAME_SHAPE∩regalloc with 2–4 movable locals; 0 of 60 MISMATCH (two samples); similarity gains on
the `FUN_0003320c` family (0.50→0.73, five functions) and `FUN_00047c6c` (0.49→0.75). Mechanism
as far as traced: declaration order → auto-symbol creation order → `AddConflictNode` prepend →
`SortConflicts` (diminishing-gap sort, strict `>`, so equal-`savings` runs come out as a
deterministic function of the input permutation) → `GiveBestReg` first-wins over
`EAX, EDX, EBX, ECX, ESI, EDI` (the 10.0a table, one table for temps and parms).

And the number that bounds the risk: **332 of 764 EXACT functions ride on an allocation tie whose
direction happens to agree** (your §4.8). Any reordering that fires on them can break them.

### The deliverable

A `RecoveredChoices`-style per-function decision (`decl_order: Option<Vec<name>>`, printc
side — `p.decls` is sorted at the end of `print_c`/`print_c_recovered`; register/temp locals
currently keep insertion (first-use) order, stack locals are frozen in storage order and must stay
frozen) whose value is **inferred from the original's bytes**, never searched with the compiler:

1. **Evidence per temp.** For each register-held local in the recovered C, the physical register
   the ORIGINAL holds it in. Source of truth: the original's instruction at the temp's defining
   site (the candidate's `MOV reg,…`/`XOR reg,reg` that materializes the temp, aligned against
   the original via `recompile_check --divergences` rows — `regalloc` rows give the pair
   `(candidate reg, original reg)` directly; equal rows give `reg == reg`). A temp whose original
   register cannot be read unambiguously (not aligned, or assigned to two different originals at
   two sites) makes the whole function **abstain**.
2. **The inverse.** State the mapping *declaration order → role assignment* as a predicate you can
   evaluate WITHOUT the compiler, derived from the mechanism above, and **calibrate nothing**:
   derive it from the three converted specimens plus the `DoubleParmRegs` table order, then
   check it reproduces the 3 winners AND the 9 non-winners of the 12-candidate ceiling set
   (the non-winners are as informative as the winners — if the predicate says a byte-exact
   order exists for `FUN_0006a720`, it is wrong). Expect the prepend+ShellSort composition to be
   the subtle part; for runs of ≤4 equal-savings temps, enumerate the composition explicitly
   rather than reasoning about it.
3. **The gate.** Fire only when (a) every movable temp has unambiguous evidence, (b) the
   predicate applied to the CURRENT order does not already reproduce the original's assignment
   (this is what keeps the 332 EXACT functions untouched — an EXACT function's current order
   already matches by definition), and (c) the predicate names exactly one order (or one
   equivalence class) that does. Otherwise abstain.
4. **Measurement, pre-registered.** Probe scale first: all 12 ceiling candidates (expect the 3
   to convert and the 9 to be untouched or improved, never regressed) PLUS the full population
   of currently-EXACT functions with ≥2 movable register temps — compile all of them at probe
   scale, not a sample (the aggregation arm lost five EXACTs to a three-function sample). Then
   one corpus round against zc27 with `scripts/war2-verdicts.sh`: the landing bar is zero
   verdict regressions and positive weighted WGSS. Pre-register the expected flips (≤3 EXACT)
   and the expected WGSS (the family and 47c6c sims, roughly +0.0004 insn-weighted) before the
   round; report the miss if it misses.

What would close the item negatively: no compiler-free predicate reproduces the 12-candidate
outcome. Report that as the result; the fitted search stays a ceiling, not a lever.

### Instruments you already have

`held-patches/permute.py` (single-function permutation probe) and
`held-patches/declorder_ceiling.py` (the batched ceiling census, corrected freeze regex). Point
both at zc27. The probe-staging trick for the emitter side: `war2_survey … --only <va,…>` prints
the recovered TUs to stdout (no files in probe mode); cut each at its final `}` into a staging
`recovered/` dir beside a copied `prelude.h` and run `recompile_check … --only` against the
zc27 manifest.

---

## Item 2 — the arg-setup MOV pairs are IR-generation order: find the source shape

### What is established (your §5)

The 31 transposed argument-setup pairs (28 functions; 5 pure two-row functions:
`FUN_000249a0`, `FUN_0004b750`, `FUN_00068bca`, `FUN_0006b496`, `FUN_00073328`) are not a
scheduler dial: the equal-`stallable` pairs flip on the final `ins->id` key, so the order is the
code generator's instruction-creation order — downstream of our C. `FUN_0004b750` follows the
stock rule at five of six identical sites and deviates at one, so the original SOURCE differed
at that site in a way that changed creation order.

Earlier probes (recorded in `byte-exact-status.md`, allocator-thread entries) found that these
do NOT move the pair: `#pragma aux … parm [edx] [eax]` with permuted arguments, nested-call vs
hoisted-temp argument, Watcom 10.6. So the shape is something else.

### The question, and how to answer it without guessing

Read the front end rather than probing blindly: OW 1.0.0 `bld/cc/c/cgen.c` (`CGAddParm` call
order when lowering a call), `bld/cg/c/bldcall.c` (`BGAddParm` prepends; `AssgnParms` reverses the
parm list before `ParmIns`), and where the **constant** parm's materialization instruction is
created relative to a **register-copy** parm's — the hypothesis to test is that a constant
argument's load is created at a different point than a variable's (e.g. folded at the call vs
materialized with the parm list), so the original's copy-first order needs a shape in which the
variable argument is created LATER than it is in ours (a temp? an expression? a different
declared parameter type on the callee — `char`/`short` constant parms lower differently?).
State the candidate shapes from the source reading FIRST, then probe each with `dumpwc` on
the 4b750 site-A shape (`void p(int x){ f(x, 2); }` with the callee declared as you hypothesize),
stock 10.0a, flags `-5r -fpi87 -s -onatx -d1+`.

Pre-register: success = one shape reproduces BOTH `FUN_0004b750`'s site A and `FUN_00073328`'s
load pair; partial = one of them; null = neither. Control: the same shape must not disturb the
five constant-first sites of 4b750 (compile the whole recovered TU with only site A changed).
If a shape is found, the lever is a per-site recovered choice with byte evidence (the
original's setup order is already extracted by `call_setup_sites` / `param_orders_from_evidence`
for const-class sites) — design it, don't land it; report the pool it would cover (the 31 pairs)
and the blast radius (every call site whose original order already matches).

---

## Conventions (same as the brief)

- Pre-register each prediction in the results document before the measurement that tests it.
- Separate compile caches per distinct compiler or distinct harness behaviour.
- `scripts/war2-verdicts.sh <baseline> <candidate>` for every comparison; quote EXACT and WGSS
  together (the comparison now prints the insn-weighted net and its WGSS delta).
- dosemu is shared with other sessions on this machine; a survey emit is ~7 min, a cache-warm
  corpus round ~15 min — budget for contention.
- Deliverable: a sibling results document (`docs/declorder-irorder-results.md`), and an entry at
  the end of `docs/byte-exact-status.md` when something lands or closes. Commit on this branch
  only.
