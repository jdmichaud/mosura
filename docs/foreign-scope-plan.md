# Foreign-module classification — design & plan

**Status:** hypotheses validated 2026-08-25 (POC); **engine implemented 2026-08-25** (Phases 1–5).
This document fixes the design and the staged plan so the work does not drift.

**Implementation:** `crates/mosura/src/analysis/foreign.rs` (engine + 10 unit tests),
`crates/mosura/examples/foreign_propose.rs` (band proposer, Phase 1), and the opt-in `--exclude-foreign <file>`
flag on `recompile_check` (denominator wiring, Phase 4). The per-binary confirmation file (Phase 2)
is **reverse-engineering data about a proprietary binary — it lives with that binary's own artifacts,
not in the repo.** Default-safe: with no confirmation the classification is exactly today's
FID/loader set (verified on WAR2: 130 foreign, 0 held). Usage (`<foreign-file>` is the out-of-repo
confirmation file):

```text
# propose bands for review (read-only):
cargo run --release --example foreign_propose -- <binary> [--native]
# preview the denominator with confirmed bands:
cargo run --release --example foreign_propose -- <binary> --confirm <foreign-file>
# audit a classification band by band (the band report, §5 Phase 1):
cargo run --release --example foreign_propose -- <binary> --report [--confirm <foreign-file>] \
    [--rec <rec.tsv>] [--memo-cut <va>]
# score with foreign excluded (compare against a run without --exclude-foreign = both numbers):
recompile_check <binary> <manifest> <src> recover <watcom> --exclude-foreign <foreign-file>
```

On WAR2 the confirmed `war2.foreign` (Miles/AIL + SciTech UVBE bands) takes foreign from 130→278
(the two bands + their reachable-private helpers), in-scope denominator 2893→2745, 28 held.

## 1. The one decision this serves

The recompilation score (EXACT / WGSS) is a fraction whose denominator is "functions we intend to
reproduce from C." A DOS/4GW game binary is not only the game: the Watcom linker concatenates the
game's object modules with **foreign** modules it did not author — the C runtime (CRT), and
licensed libraries (WAR2: Miles/AIL audio, SciTech/UVBE VESA). Foreign code is reproduced by
*linking the library*, not by decompiling it; counting it measures the toolchain, not the port.

mosura already excludes *some* foreign code. This plan is about closing the gap **generically** —
a binary-agnostic engine, with every binary-specific fact held behind a data boundary — so it
never mis-classifies another binary's own code as foreign.

## 2. What is already built (do not reinvent)

- **`Function::is_identified()`** (`program/function.rs`): a function with a non-default name
  (from a **FID** signature match or a loader symbol) is "identified." The doc-comment there
  already states this is "what decides whether a function belongs in a recompilation denominator."
- **`kind_of` / `kind_of_insns`** (`examples/war2_survey.rs`): manifest `kind` = `library` when
  identified, else `user`; a `user` function whose original insns trip
  **`buildconfig::looks_hand_written`** (segment ops, `INT 0x21`, `CS:[…]`, `PUSHF`…) becomes
  `asm`. The survey excludes `library` and `asm` from the denominator.
- **FID** (`analysis/fid/*`): fingerprint matcher against packed `.fidb` / `.mfid.gz` databases.

So today's foreign set = **FID-named ∪ hand-written-asm**. The gap: FID only knows libraries it
has a database for.

## 3. Validated findings (2026-08-25 POC)

Method: `foreign_propose <binary> --facts` (one analysis pass → per-function TSV: VA, size,
prologue, call-graph degrees, foreign-fingerprint, anchor) reduced by an ad-hoc script. Binaries:
WAR2.EXE (deep), WRMS.EXE (Worms, degradation case), DESCENTR.EXE (overtraining case). The `--facts`
dump is a kept tool, so the table below is reproducible.

| # | Hypothesis | Verdict | Evidence (WAR2 unless noted) |
|---|---|---|---|
| H1 | FID seeds known libraries, no game false-positives | **CONFIRMED** | 130 CRT named (memset/sprintf/…); **0% FID hits below the game/lib seam**; WRMS 107 |
| H2 | Anchor strings seed foreign functions FID misses | **CONFIRMED** | 66 AIL funcs via self-naming `AIL_startup()` refs; **0 of them FID-known** |
| H2b | Generic anchor regex over-captures game strings | **CONFIRMED** | 3 stray singletons: `Build.c`, `count.c` (game debug/trace strings that merely contain a `.c` token — WAR2 has no debug info), `UVBELib` (real SciTech, 1 anchor) |
| H3 | Locality clustering isolates the module | **CONFIRMED — load-bearing** | AIL = one cluster of 63 anchors in `0x5191e..0x56815`; game strings stay singletons |
| H4 | A foreign module is a contiguous VA band | **CONFIRMED** | band = 68 funcs, the 5 non-anchored ones are AIL JMP-thunks + a cdecl helper → 100% foreign |
| H5 | Codegen fingerprint is bimodal (convention) | **CONFIRMED** | foreign leads `56 57`(save esi/edi, cdecl)=93% of band vs 6% of game; game = push ebx/ecx/edx + `89 e5` (__watcall param regs) |
| H5b | Fingerprint alone is sufficient | **REFUTED** | 156 game funcs also lead esi/edi → fingerprint is *corroboration within a band*, not a standalone seed |
| H6 | Reachability extends seeds and protects shared code | **CONFIRMED** | 66 seeds → closure 337; **202 reachable only-from-foreign** (private helpers) + **69 also called by game** (shared — must NOT drop) |
| H7 | Modules are concatenated game-first, libs-last (master seam) | **CONFIRMED** | `0x10000..~0x50000`: 91–100% watcall, 0% FID, ~3% foreign-fp = game. `0x50000+`: FID 10–26%, foreign-fp 30–56%, watcall falls = library zone |
| H8 | Degrades safely when signals are absent | **CONFIRMED** | WRMS (release, no traces): 0 anchors → falls back to FID's 107, invents nothing |
| H9 | Does not overtrain: source-refs are not presumed foreign | **CONFIRMED** | Descent's *entire* anchor set (11 funcs) = its **own** modules `gamesave.c`/`game.c`/`piggy.c`/`fuelcen.c`/`ntmap.c`; auto-flagging would delete the game |
| H10 | The dominant signal varies by binary | **CONFIRMED** | WAR2 = self-naming traces (AIL); Descent = FID+fingerprint (its libs don't self-name); WRMS = FID-only — only the composite generalizes |

Load-bearing conclusions:
- **No single signal is sufficient.** FID misses un-databased libs (AIL/SciTech); anchors are
  absent in release builds and over-capture game strings; the fingerprint has a ~3–6% game
  baseline; reachability depends on a complete call graph. The reliable classifier is the
  **composite**, and the reliable clustering key is **address locality**, never a string prefix.
- **The game zone is provably clean** (FID 0%, foreign-fp ~3%) — the safe core of the denominator.
- **The tool must never decide foreign-vs-game by itself, and the human must not have to hunt.**
  The proposer lists candidates; the developer confirms the ones they *recognize* as foreign and
  ignores the rest — default-safe keeps every unconfirmed candidate in scope, so no `reject` and no
  binary-scanning is required for stray matches (WAR2's `Build.c`/`count.c` are just game trace
  strings that happen to contain `.c`; they need no action). `reject` is only for carving a known
  game function out of a *confirmed* foreign span. Only a human — or the fingerprint within a
  confirmed band — ever promotes a band to foreign.

## 4. Design

A **generic engine** consuming **binary-specific data behind a boundary**.

### 4.1 Generic engine (no library names, no per-binary tuning)

1. **Facts** — enumerate functions, extents, prologue bytes, the direct/indirect call graph, and
   code→data references. (`foreign::extract_facts`; dump via `foreign_propose --facts`.)
2. **Seed signals** — each is *positive-only*:
   - **S1 FID** — existing `is_identified` (known libraries + loader symbols).
   - **S2 Anchor** — a function that references a *structurally* anchored string: self-naming
     `^ident\(`, source-ref `\w+\.(c|cpp|asm)`, or banner (copyright/version). Structural shapes
     only — the exact patterns live in data (§4.2), the *shape grammar* is generic.
   - **S3 Fingerprint** — a prologue matching the foreign-convention signature (save esi/edi/ebp +
     read args from stack, no __watcall param-register use). Used to *corroborate/extend within a
     band*, never as a standalone seed (H5b).
3. **Bands** — cluster seed functions by VA locality (gap threshold). A band is the human-facing
   unit: address range, function count, dominant anchor class, representative string, fingerprint
   agreement %.
4. **Spread — IMPLEMENTED: reachability only.** From a confirmed band's members, call-closure
   members whose callers are *all* foreign are foreign (corroborated by fingerprint or the band
   span); members also called by in-scope code are **shared** and are held, never dropped.
   **NOT yet implemented: contiguity-fill to the module seams.** A confirmed band today spans only
   `[first seed VA, last seed VA]`, so the unanchored head/tail of a module (e.g. WAR2's 191 AIL-
   tail functions past the last `AIL_` string) is reached only if reachability happens to walk into
   it. Filling to the linker's alignment-padding seams would close that — see §6, deferred.

### 4.2 Data behind the boundary (per-binary / external — the only place specifics live)

- FID databases (`.fidb` / `.mfid.gz`).
- The anchor **shape** patterns (a small pattern list — structural, not library names).
- The human's **string selections**: which anchor *strings* name a foreign module (and which name
  the game's own — a `reject`). The human picks strings from the proposed bands; the engine derives
  the functions and the address span. **Addresses are never hand-authored.** Default empty ⇒ no
  exclusions beyond today's FID+asm.

### 4.3 Invariants (the anti-drift guardrails)

1. **Positive-evidence-only.** In-scope unless *positively* shown foreign. Absence never excludes.
2. **Human-confirmed bands.** The tool proposes bands; a human ticks foreign vs in-scope. The
   engine never presumes a source-ref/self-naming band is foreign (it may be the game's own).
3. **Generic engine / data boundary.** Engine = structural shapes + graph algorithms only. All
   binary knowledge is data. No `"AIL"`/`"SciTech"` literal ever enters the engine.
4. **Non-invasive.** On a binary with no anchors it degrades to FID-only; on a non-Watcom binary
   the fingerprint shapes simply don't fire. It never fabricates foreign bands.
5. **Auditable.** Every excluded function records its evidence chain (FID:name / anchor:string /
   band:confirmed / reachable-from:seed) so any exclusion can be challenged.

## 5. Plan (staged; each phase is independently reviewable)

- **Phase 0 — Instrumentation.** *(DONE)* `foreign_propose --facts` (the kept fact dump) + an
  ad-hoc reducer prove the signals across three binaries. Findings in §3.
- **Phase 1 — Band proposer (read-only).** *(DONE)* `examples/foreign_propose.rs` emits the
  human-facing band report per binary (range, #funcs, anchor class, example, fingerprint
  agreement) and a classification preview. Changes no denominator.
  **`--report` (2026-08-31)** is the auditable form of the same pass, so §4.3.5 can actually be
  exercised: per band, the span accounting and a *deterministic* spot-check sample (the sampling
  rule is printed, so re-running the command reprints the same rows); then `held` in its own
  section with its own row/weight/EXACT accounting, never folded into a band; then the denominator
  table. `--rec <rec.tsv>` joins a `recompile_check --out` measurement so each section carries its
  corpus weight (WGSS Σ orig_n·sim / Σ orig_n, the canonical formula). `--memo-cut <va>` prints
  one extra row: what a **hand-drawn address cut** would score, and the gap between it and what
  evidence covers. That address is supplied on the command line and labelled as *not evidence* —
  it is the line the classifier has to earn, and it must never become a constant (§4.2).
- **Phase 2 — Confirmation format.** *(DONE)* `foreign::Confirmation` line format
  (`foreign|reject <string> <reason>`), passed by path to the tools. The file is per-binary RE data
  kept out of the repo (with the binary's own artifacts). **The human names STRINGS, never
  addresses** — a distinctive substring of a
  proposed band's string (or a FID library name). The engine resolves each string to the functions
  it anchors and derives the module span by locality clustering. Behind the data boundary; empty = safe.
- **Phase 3 — Engine.** *(DONE)* `analysis::foreign`: `extract_facts` → `propose_bands` →
  `classify(facts, conf) → Classification { class, reason, held }`. Foreign = FID ∪ confirmed-band
  ∪ reachability-private(corroborated) − rejects; uncorroborated reachables are **held**. `Asm`
  stays with the survey's existing `kind_of_insns` (foreign detection is orthogonal).
- **Phase 4 — Denominator wiring.** *(DONE)* `recompile_check --exclude-foreign <file>` excludes foreign
  from the denominator exactly as `library`/`asm` are, and reports the count separately. Opt-in and
  default-off, so a run **without** `--exclude-foreign` reproduces today's number; comparing the two runs is
  the honest "both numbers" (the same idiom as `--include-library`). *A full corpus round to
  measure the WGSS/EXACT delta is a separate, JD-run activity.*
- **Phase 5 — Generalization gate.** *(DONE)* Proposer run on WAR2 / Descent / WRMS / BLACK: sane
  bands or none, no per-binary tuning, and **no game-module false exclusion** (Descent's own
  `*.c` bands are proposed but never auto-foreign).

### Guardrail tests (so we do not drift) — all in `foreign.rs` unit tests

- **Empty confirmation changes nothing** — `empty_confirmation_is_fid_only`,
  `empty_confirmation_no_fid_reachability` (FID never drives reachability).
- **Source-ref band not auto-foreign** — `source_ref_band_proposed_but_not_auto_foreign`.
- **A shared helper (reachable from game) is never dropped** — `confirmed_band_and_reachability_and_shared`.
- **Uncorroborated reachable is held, not dropped** — `reachable_uncorroborated_is_held_not_dropped`.
- **Locality, not name, clusters** — `locality_splits_scattered_anchors_from_a_tight_band`.
- Fingerprint shapes are measured from ground truth (§3), not hand-tuned — `fingerprint_bimodal`.

## 6. Coverage, open risks & the decision that stays with JD

**Confirmed coverage is a LOWER BOUND — state it next to the 278.** On WAR2 the foreign-ish zones
hold ~939 functions (AIL `0x5191e–0x5c000` ≈ 259; CRT/SciTech `0x5c000–0x7c520` ≈ 680, of which FID
already names 128). The confirmed classification excludes **278** — roughly **a third** of the
foreign code. What it misses: the 191 unanchored AIL-tail functions past the last `AIL_` string
(no contiguity-fill, §4.1.4); the ~130 silent SciTech functions the single UVBE banner can't seed
(they emit no string — see §3 H2/H10); and the ~470 CRT-zone functions above `0x5c000` that FID
misses and no anchor covers. So the denominator decision JD is being asked to make is "exclude the
278 we can prove," not "exclude all foreign" — the rest stays in scope, costing WGSS but never
risking a game false-positive.

**Three mechanisms would lift coverage without breaking the invariants (deferred, JD to greenlight):**
- **(a) Module-seam fill — VERIFIED, NOT worth building as proposed (2026-08-25).** Extend a
  confirmed band across the linker's zero-padding-run seams to reach a module's unanchored head/tail.
  Measured on WAR2 (`dumpseams`, a throwaway probe): the seams are **real but weak** — 171 gaps have
  a leading zero-run ≥4 bytes, 117 ≥8, but the **maximum run is 15 bytes; none ≥16**. So pure
  seam-fill has a **threshold cliff**: at T≤8 it is bounded and clean (AIL band → `0x50b10..0x583c4`,
  +57 tail funcs, 0 game-call FP), but at T≥16 nothing stops it and it engulfs the whole binary
  (3023 funcs, 1125 FP). Two further findings: the **fingerprint guard actively defeats it** —
  it collapses back to the 68-func anchor band, because AIL's watcall-compiled internals (the very
  `held` functions we want) sit at the band edges; the guard that *does* work is a **calls-into-game
  check** (a library never calls up into game logic, `0x10000–0x48000`), which is threshold-robust
  (bounds even T=64) and catches +57–84 AIL-tail incl. the watcall internals, with 0 game source-refs
  and boundary functions that decompile as AIL (some edge functions are misidentified/garbled, not
  clean). **Verdict:** the padding runs are too weak to be a safe boundary; the real lever is the
  call-direction guard, which is a *reachability refinement*, not a seam. The gain is modest and
  **AIL-only** (nothing for the CRT/SciTech zones). If ever pursued, build it as a call-direction-
  guarded band extension behind an explicit opt-in — not raw seam-fill. §4.1.4 stays reachability-only.
- **(b) FID-dense bands.** `Band` already carries `fid_in_span`, but bands only form from anchors, so
  a seam-delimited run full of FID names (the CRT) is never proposed. Propose such a run as a band
  labelled by its FID names and let the human confirm "CRT" — closes most of the ~470 CRT-zone miss.
- **(c) Resolve `held`.** A held function has no anchor, and the grammar names strings only, so
  nothing the human can write ever promotes it — AIL internals compiled watcall stay in forever. Add
  a per-band opt-in (`foreign AIL_ … +held` = "inside this confirmed band, trust reachability") —
  still no addresses, still opt-in.

**Standing risks:**
- **Indirect calls (`CALLIND`).** Reachability from a partial call graph can over-claim
  "only-from-foreign." Mitigation: reachability only demotes when fingerprint or the band span also
  agrees; otherwise the function is **held**, not dropped. Mechanism (c) above deliberately relaxes
  this per-band, at the human's request.
- **Watcall-compiled library functions** in the mixed library zone look game-shaped; only the
  composite (FID + locality + reachability) separates them. The clean case (AIL) is easy; the CRT
  zone is the hard case.
- **Series hygiene.** A `--exclude-foreign` run is a different measurement series; its TSV is stamped
  and the census announces it (`docs/measurement-rules.md`). The FULL denominator stays canonical
  until JD decides.
- **Policy is JD's.** Whether — and how aggressively — to exclude the library zone from the
  denominator is a measurement-policy choice ("recompilation is the goal"). The engine *surfaces*
  evidence and proposes bands; JD decides what the denominator counts.
