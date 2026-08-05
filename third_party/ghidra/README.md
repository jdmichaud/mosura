# Vendored Ghidra language files (test-path subset)

A verbatim subset of the pinned Ghidra checkout, vendored so `git clone && cargo test` is
fully self-contained — no network fetch, no SLEIGH compile, and no *silent skip* when the
sibling checkout is absent (SLEIGH-gated tests used to `return` early without tables; the
`sleigh_canary` test now fails loudly instead).

- **Provenance**: `github.com/NationalSecurityAgency/ghidra`, tag **`Ghidra_12.0.3_build`**,
  commit **`09f14c92d3da6e5d5f6b7dea115409719db3cce1`** — the same pin `scripts/setup-ghidra.sh`
  fetches and verifies. The `.sla` files are the deterministic sleigh-compile of that pin's
  `.slaspec` sources (the compile `setup-ghidra.sh` performs); everything else is byte-verbatim
  from the checkout.
- **Contents**: `Processors/{x86,AARCH64,RISCV,68000,Z80}/data/languages/` (the six language
  families mosura loads: specs + compiled `.sla`), `Processors/{x86,AARCH64,RISCV,68000}/data/patterns/`
  (the **Function Start Search** byte patterns — Z80 ships none), and `datatests/` (the decompiler
  conformance fixtures). `LICENSE`/`NOTICE` are Ghidra's own (Apache-2.0) — this subset is redistributed
  under that license, unmodified.
- **Resolution order** (`crates/mosura/src/paths.rs`): `GHIDRA_SRC` env → the sibling checkout
  (`<workspace>/../ghidra`) → this vendored copy. A developer with a checkout sees the checkout;
  a bare clone falls back here.
- **Verify / refresh**: `scripts/verify-vendored-ghidra.sh` diffs this copy against the pinned
  checkout (run it after any pin bump, then re-commit; it refuses to verify against a checkout
  that is not at the pin). The rest of the checkout (decompiler C++ source, oracle tools, golden
  regeneration) is still fetched by `setup-ghidra.sh` — vendoring removes Ghidra only from the
  *test* path.
