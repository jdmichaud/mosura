# Developing mosura

How the repository is laid out, how to set up the oracle, how to test, and where the rules are. The
porting principle itself — port Ghidra's actual logic, validated against its IR, never an approximation —
and the day-to-day workflow are in [`AGENTS.md`](../AGENTS.md); read that first.

## Crates

| crate | role |
| --- | --- |
| `mosura-core` | the port: `sleigh::` (the `.sla` loader, engine and emulator), `analysis::` (loaders, auto-analysis, FID), `decompile::` (the Varnode graph, the `Action`/`Rule` pipeline, the C printer, the emit arms), `recompile::` (translation units, the toolchain driver, verdicts, gates) |
| `mosura-api` | operations, options, tables, the `.tbl` store and sessions (internal) |
| `mosura-capi` | the C ABI, `libmosura`; the header `include/mosura.h` is generated from it |
| `mosura` | the safe Rust binding over the C ABI |
| `mosura-cli` | the `mosura` binary, written against the binding |
| `mosura-dev-ops` | the developer tier: `dev.*` operations behind the `dev-tools` feature |
| `xtask` | `cargo xtask <baseline|fid-build|omf-uber|devcfg|data-export|data-list|header|dist>` |

The design of the product surface (operations, options, tables, the store, the C ABI, the CLI) is
[`product/architecture.md`](product/architecture.md); the plan that built it is
[`product/plan-wp7-2026-09-05.md`](product/plan-wp7-2026-09-05.md).

## Where things are

| path | contents |
| --- | --- |
| `crates/mosura-core/src/{sleigh,analysis,decompile,recompile}/` | the port |
| `crates/mosura-core/tests/` | conformance datatests, disassembly goldens, the decompiler corpus, ground truth, the guards |
| `third_party/ghidra/` | the vendored Ghidra 12.0.3 processor tables, byte-identical to tag `Ghidra_12.0.3_build` (`scripts/verify-vendored-ghidra.sh` checks) |
| `specs/`, `data/fid/` | mosura's own compiler specs and FID databases (embedded at build time) |
| `oracle/` | the oracle capture tools (`capture`, `capture_trace`, `capture_typeprop`), the fixture corpus (`fixtures/`), the analysis corpus (`analysis-corpus/`), the ground-truth programs |
| `goldens/` | disassembly and analysis goldens |
| `include/mosura.h` | the committed C header (`cargo xtask header` regenerates it) |
| `docs/` | plans, the product architecture, the runbooks, the measurement rules, the bug and finding records |
| `scripts/` | setup, CI, gates and census scripts |

## The oracle

The pinned Ghidra *source* is the reference for porting and for regenerating goldens. It is needed by the
oracle tier only — a bare clone builds, runs and passes its self-contained tests without it.

```sh
sudo apt-get install -y build-essential bison flex binutils-dev libbfd-dev zlib1g-dev
scripts/setup-ghidra.sh     # shallow-clone the pin beside this repo (or at `ghidra_src` in dev-config.toml), verify the commit, compile the .sla
scripts/setup-oracle.sh     # additionally build the Ghidra C++ oracle tools under oracle/
```

Machine-specific locations — the Ghidra checkout, toolchain installs, user-provided binaries, the compile
cache, the subject profile — live in the gitignored `dev-config.toml`; [`dev-config.example.toml`](../dev-config.example.toml)
lists every key with its default. Nothing reads the environment (see the guards below).

## Testing

```sh
cargo test                            # SLEIGH conformance + the decompiler corpus against Ghidra; oracle-backed tests skip without the pin
cargo xtask baseline                  # regenerate the disassembly / p-code goldens from the oracle
scripts/gate-compiler-free.sh         # every test binary with PATH stripped: the library needs no toolchain to build or test
cargo test -p mosura-core --test ground_truth_recompile_arms -- --ignored   # the gcc ground truth of the emit arms (opt-in, run at plan closure)
```

CI (`.github/workflows/ci.yml`, job `clean-clone`) runs `scripts/ci-clean-clone.sh`: a fresh checkout plus
the pinned Ghidra, the full `cargo test --workspace`.

Two grounding examples remain in `crates/mosura-core/examples/`: `dumpc` dumps the decompiled C (or the
raw / pre-pipeline IR) of one fixture, `trace` the pipeline's trace of it:

```sh
cargo run -q --example dumpc -- oracle/fixtures/x86_64_tiny.xml           # a bundled fixture by path; a bare stem resolves in the pinned datatests
cargo run -q --example dumpc -- oracle/fixtures/x86_64_tiny.xml --raw     # the post-decompile IR; --pre = the lifted p-code before any action
```

## The developer tier

Oracle sweeps, censuses, ground truth through gcc, MVE fixtures and probes are `dev.*` operations behind the
`dev-tools` feature. `mosura ops --dev` lists them, `mosura dev <op>` runs one; a release build has none of
them and answers "not built in".

```sh
cargo run -q -p mosura-cli --features dev-tools -- -S - dev bench                    # per-fixture timing, worst first
cargo run -q -p mosura-cli --features dev-tools -- -S - dev oracle.sweep             # mosura's C vs Ghidra's over the fixture corpus
cargo run -q -p mosura-cli --features dev-tools -- -S - dev groundtruth.recompile    # source → gcc → decompile → gcc verdicts
cargo run -q -p mosura-cli --features dev-tools -- -S - dev mve.fixtures dev.check=true   # the self-compiled Watcom fixtures are what the tests expect
```

## Measuring

The recompile pipeline is measured by corpus rounds. [`corpus-round-runbook.md`](corpus-round-runbook.md)
says how to run one (`mosura round run`, `round compare`, `gates`) and what "stable" means;
[`measurement-rules.md`](measurement-rules.md) says how a number may be quoted, what the identity gate is,
and when a change needs a round. A defect fix ships a pinning test; a behaviour-neutral change passes the
identity gate; an intended change to the emitted text goes through a round and lands on the verdict
comparison.

## Guards

Three tests keep the repository generic and build-hermetic, and they run in the default suite:

| test | rule |
| --- | --- |
| `tests/no_env.rs` | the library, the CLI, the examples and the tests read no environment variable |
| `tests/no_subject_names.rs` | no tracked file names a subject binary |
| `tests/no_machine_paths.rs` | no tracked file names a developer's home directory |

Fixtures are self-compiled minimal examples, never bytes of a subject; the compile cache and the subject
profile live outside the repository and are reached through `dev-config.toml`.
