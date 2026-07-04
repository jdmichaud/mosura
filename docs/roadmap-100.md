# Roadmap to the 100% Ghidra port

Governing rules: [`../CLAUDE.md`](../CLAUDE.md). Working backlog: [`../TODO.md`](../TODO.md).
This document is the top-level plan for reaching a complete port; it changes only by
deliberate decision, not per-session.

## Definition of done

"100%" is **multi-arch, reached in stages**: first **x86-64 complete** (all four properties
below on the x86-64 corpus), then the other SLEIGH-supported architectures built on that
foundation (per-arch corpus + removal of x86-64-scoped adaptations).

The corpus similarity score is a diagnostic, never the definition. Done means:

1. **Mechanism coverage** — every rule/action/mechanism in Ghidra's decompiler source is
   either PORTED (cited) or tracked BLOCKED (cited reason). Zero silent gaps.
2. **IR parity** — on the corpus, the mosura↔Ghidra rule-firing trace-diff shows zero
   divergence, stage by stage — not merely similar final C.
3. **Output parity** — `--c` output equivalent on the corpus (modulo documented rendering
   trivia) and no regressions on binaries beyond the corpus.
4. **Analysis-track parity** — the A0–A7 auto-analysis port (binary file → what to
   decompile) passing its Program-state snapshot gates.

## Phase 0 — Coverage matrix (next; one focused session)

Mechanically extract Ghidra's authoritative inventory — the full oppool1 rule list and
universalAction action list (coreaction.cc:5462+), heritage mechanisms (heritage.cc),
fspec/prototype machinery, jumptable models, printc emitters — and diff it against mosura.
Deliverable: `docs/coverage.md`, one line per mechanism:
`PORTED@commit | HELD(reason) | BLOCKED(dep) | MISSING`.
This turns the remainder into a burn-down list and finds every not-yet-stumbled-on gap at
once (the missing `earlyremoval` action was found only by accident via trace-diff; the
matrix finds all of those systematically). All later phases work off this file.

## Phase 1 — Decompiler core completion (dependency order)

- **1a. SubVariableFlow completion** (in flight): land the measured 5-driving-rule wiring
  (net-positive, pre-approved) → measure tryReturnPull's effect (int4 return widths; the
  port is landed and inert pending the wiring) → diagnose the loopcomment divergence → fix
  the RuleShiftPiece low-piece divergence → unblock SubZext/Piece2Zext → Stage 4 (sext
  tracer, CALL/CALLIND/BRANCHIND pulls) → resolve the AndDistribute↔HumptyOr ping-pong.
  Unblocks: return widths, heritage partition-broadening, the held rules.
- **1b. Rule/action tail** (mechanical, driven by the Phase-0 matrix): earlyremoval,
  propagatecopy gate alignment, every remaining ruleaction.cc rule and coreaction.cc
  action — faithful, unit-tested when unexercised by the corpus.
- **1c. Divopt de-fusion + switch/jumptable** (the known coupled cascade): RuleSub2Add into
  the main pool (Ghidra's placement) + fix the non-Ghidra switch/jumptable code that move
  exposes + find_form signed path + wire RuleDivTermAdd + retire the fused recognizer.
  Bundled with P7 structuring (ruleBlockOr/Goto/Switch, condition negation) and the CFG
  residuals (condconst lifter jump-target, ifswitch) — same neighborhood. Biggest remaining
  decompiler effort.
- **1d. Prototypes done right (P6)**: the AncestorRealistic state machine (solid/kill
  thresholds, checkConditionalExe), multi-pass ParamActive with the mainloop flip, param
  passthrough + XMM args, the void-fixture upstream divergences (e.g. dupptr's non-Ghidra
  const-fold), guardInput unification, guardLoads + discoverIndexedStackPointers, the
  2-input INDIRECT iop model. Sequenced after 1a (subvar reshapes the graph these decide on).
- **1e. Presentation tail (P5/P8)**: NameVars naming, global-variable naming, branchless
  boolean flags, irreducible-CFG gotos, the nan CBRANCH residual, deferred cast items.

## Phase 2 — Validation hardening (cheap, continuous; defines "done" for 2–3)

Promote the trace-diff from a debugging tool to a CI gate (zero-firing-divergence target
per fixture); make `--c` textual equivalence the reported score; grow the corpus with real
binaries (the 60 fixtures under-sample switches/floats/structs).

## Phase 3 — Analysis track (A0–A7; the untouched second half)

A0 oracle (analyzeHeadless backend + snapshot v2) → A1 Program model → A2 ELF loader ∥
A3 framework → A4 disassembly/function discovery → A5 references/SymbolicPropogator (the
heavyweight) → A6 decompiler-driven analyzers (needs Phase 1) → A7 tail. Java→Rust with the
same discipline: oracle-gated, premise-verified, faithful-only. A0/A1 can start in parallel
with late Phase 1 if throughput is wanted.

## Phase 4 — Multi-arch (after x86-64 is complete)

Extend to the other SLEIGH-supported architectures on the completed x86-64 foundation:
per-arch corpus + oracle goldens; remove the x86-64-scoped adaptations (little-endian-only
paths, laned-register scoping, SysV-specific assumptions) by porting Ghidra's general
mechanisms; each arch gated on the same four done-properties.

## Working method (how every phase executes)

One persistent agent; **instrument-first diagnosis** (see CLAUDE.md — trace-diff/oracle
evidence names the mechanism before any source-reading hypothesis); premise verified
read-only before any code; new code is always a faithful port; corpus-moving lands gated
with measured deltas; every commit green and subsystem-coherent; findings checkpointed to
memory at green boundaries.
