# CLAUDE.md

mosura — a Rust **port of Ghidra's logic** (SLEIGH disassembler, p-code interpreter, decompiler),
validated against Ghidra as the golden oracle; shipped as a library with a C API and a command line,
and extended with a recompilation pipeline that judges the recovered C against the original bytes.

- **How to work on this project** → [`AGENTS.md`](AGENTS.md): the owner's directives, the porting
  principle, the decision rule, the oracle, the quality bar, conventions.
- **Before quoting a number, retiring a claim, or trusting an instrument** →
  [`docs/measurement-rules.md`](docs/measurement-rules.md).
- **Setup, layout, tests, the developer tier** → [`docs/development.md`](docs/development.md).
- **What's left to do** → [`TODO.md`](TODO.md) (the owner's backlog) and
  [`docs/tasklist-2026-09-08.md`](docs/tasklist-2026-09-08.md) (queued items from the second subject).
- **The plans** → [`docs/roadmap-100.md`](docs/roadmap-100.md) (the road to a complete port:
  x86-64 first, then multi-arch, every arch gated on the same four done-properties; phases 0–4),
  [`docs/port-plan.md`](docs/port-plan.md) (the faithful decompiler port),
  [`docs/product/architecture.md`](docs/product/architecture.md) (the library, C API, store and
  CLI — implemented).

Detailed per-feature implementation notes live in `.claude/memory/mosura-project.md`.
