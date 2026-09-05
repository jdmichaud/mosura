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

mosura carries the data it needs: the pinned Ghidra processor tables (`third_party/ghidra/`,
byte-identical to tag `Ghidra_12.0.3_build`), its own compiler specs and its FID databases are
embedded into the library at build time, so a bare clone builds and runs with a Rust toolchain
(rustup) alone — no Ghidra checkout, no environment variable:

```sh
cargo run -q --example dumpc -- modulo        # decompiled C of a bundled x86-64 fixture
cargo run -q --example dump  -- modulo --ir   # disassembly + p-code IR
cargo test                                    # self-contained
```

An override directory is consulted first, file by file (`--data-dir <dir>` on every front-end);
`cargo xtask data-export <dir>` writes the embedded data out to jump-start one.

The pinned Ghidra *source* is the reference for porting and for regenerating goldens (the
DEV-ORACLE tier), not for running:

```sh
sudo apt-get install -y build-essential bison flex binutils-dev libbfd-dev zlib1g-dev
scripts/setup-ghidra.sh     # shallow-clone the pin beside this repo (<workspace>/ghidra/, or
                            # `ghidra_src` in dev-config.toml), verify the commit, compile the .sla
scripts/setup-oracle.sh     # additionally build the Ghidra C++ oracle tools
```

Machine-specific locations (the checkout, toolchains, user-provided binaries) live in the
gitignored `dev-config.toml`; `dev-config.example.toml` lists every key with its default.

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
