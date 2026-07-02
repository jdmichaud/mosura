# CLAUDE.md

mosura — a Rust **port of Ghidra's logic** (SLEIGH disassembler + p-code interpreter +
decompiler), validated against Ghidra as a golden oracle.

- **How to work on this project** → [`AGENT.md`](AGENT.md): the porting principle, the
  oracle, the verification/quality bar, layout, and conventions.
- **What's left to do** → [`TODO.md`](TODO.md).

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

