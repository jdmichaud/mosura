# CLAUDE.md

mosura — a Rust **port of Ghidra's logic** (SLEIGH disassembler + p-code interpreter +
decompiler), validated against Ghidra as a golden oracle.

- **How to work on this project** → [`AGENT.md`](AGENT.md): the porting principle, the
  oracle, the verification/quality bar, layout, and conventions.
- **What's left to do** → [`TODO.md`](TODO.md).
- **The plan to 100%** → [`docs/roadmap-100.md`](docs/roadmap-100.md): multi-arch, staged
  x86-64-first; the four done-properties; phases 0–4.

Detailed per-feature implementation notes live in `.claude/memory/mosura-project.md`.

** THIS IS A PORT OF GHIDRA. DO NOT MAKE UP SOME CODE. ONLY PORT GHIDRA's CODE **

## Faithful Ghidra ports are authoritative

A faithful port of Ghidra's actual C++ — a rule, action, or subsystem that matches Ghidra's
source — is correct by construction and authoritative. It stays. The corpus is a diagnostic,
not the target: when a faithful port appears to move the corpus the "wrong" way, that is
evidence that some **non-Ghidra** code is wrong — an invented heuristic, an approximation, a
mis-port, or a still-missing faithful piece. Change that code so Ghidra's real logic composes.
Only non-Ghidra code is ever in question. See [`AGENT.md`](AGENT.md).

No adaptation is grandfathered. Any deviation from Ghidra's actual logic or structure —
however it was justified or "accepted" earlier — is canceled the moment it stands between us
and a faithful port; replace it with Ghidra's real structure. A past decision to approximate
never protects the approximation. (This does not touch faithful cross-language translations
that preserve Ghidra's behavior — those ARE the port; only code that diverges from what
Ghidra actually does is in question.)

New code is ALWAYS a faithful port — never a hypothesis to test-and-revert. Before writing
any code, ground it READ-ONLY until you have verified the premise: that this is Ghidra's
ACTUAL mechanism for the goal and that it truly produces this result in our pipeline. Do not
implement on a guess and measure-then-revert.

**Instrument first, hypothesize second.** When the question is "which Ghidra mechanism
produces X?", do NOT chain source-reading guesses — ask Ghidra directly: run the rule-trace
diff (`scripts/trace-diff.sh <fixture>`, `oracle/capture_trace --trace`) and/or oracle IR
dumps so the firing evidence NAMES the mechanism, then read the source to understand what
was named. Empirics before theories: one trace beats a chain of plausible-but-wrong premise
checks. Reverting is reserved for PRE-EXISTING
non-Ghidra adaptations (the cleanup above); code written now must be faithful enough that it
never needs reverting. **A revert of newly-written code is a process failure — stop and
investigate why non-faithful code was generated (it means "only port Ghidra" was broken).**

