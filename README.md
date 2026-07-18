<p align="center">
  <img src="assets/logo.svg" alt="mosura" width="128">
</p>

# mosura

**mosura** is a faithful reimplementation of [Ghidra](https://ghidra-sre.org/)'s
reverse-engineering logic — its SLEIGH disassembler, p-code interpreter, and C
decompiler — as a Rust command-line tool and library (not Ghidra's UI). Every stage
is a from-source port of Ghidra's own C++, validated against Ghidra itself as a
golden oracle.

The SLEIGH engine is complete and byte-exact across six architectures (x86-64,
AArch64, ARM, MIPS, PowerPC, 6502) from a single data-driven interpreter. The
decompiler — a faithful port of Ghidra's `Action`/`Rule` pipeline (SSA heritage,
simplification rules, type/stack/argument recovery, jump-table + control-flow
structuring, C emission) — is well advanced and scored continuously against Ghidra's
own C output.

## User quick start

mosura reuses Ghidra's compiled SLEIGH tables and decompiler datatests, so it runs
against a pinned Ghidra source checkout as its reference. One-time setup:

```sh
# 1. Place a Ghidra 12.0.3 source checkout beside this repo (git tag Ghidra_12.0.3_build):
#      <workspace>/ghidra/    reference source
#      <workspace>/mosura/    this repo
#
# 2. Install prerequisites (Debian/Ubuntu) — plus a Rust toolchain (rustup):
sudo apt-get install -y build-essential bison flex binutils-dev libbfd-dev zlib1g-dev

# 3. Build the reference oracle and compile the SLEIGH specs (one command):
scripts/setup-oracle.sh
```

Then decompile one of the bundled x86-64 fixtures:

```sh
cargo run -q --example dumpc -- modulo        # decompiled C
cargo run -q --example dump  -- modulo --ir   # disassembly + p-code IR
```

mosura is early-stage: it currently decompiles the bundled Ghidra datatest fixtures
rather than arbitrary binaries.

## Developer quick start

After the setup above, the test harness runs the whole port against the oracle:

```sh
cargo test                            # SLEIGH conformance + decompiler corpus vs Ghidra
cargo xtask baseline                  # regenerate disasm/p-code goldens from the oracle
cargo run -q --example perf_corpus    # per-fixture timing, worst first
```

- Source lives in `crates/mosura/src/`: `sleigh::` (the `.sla` loader, engine, and
  emulator) and `decompile::` (the Varnode graph, the `Action`/`Rule` pipeline, and
  the C printer).
- `tests/decompile_corpus.rs` scores mosura's C against Ghidra's (via
  `oracle/capture --c`); `tests/conformance_datatests.rs` and `tests/disasm_golden.rs`
  hold the SLEIGH baselines.
- **The porting principle and workflow are in [`AGENT.md`](AGENT.md)**; per-subsystem
  plans and the roadmap are in [`docs/`](docs/). The rule: port Ghidra's actual
  logic, validated against its IR — never an approximation.

## License

Licensed under the **Apache License 2.0** (declared in the workspace `Cargo.toml`),
matching Ghidra's own license. mosura is a from-source port of Ghidra and links no
GPL-licensed code.
