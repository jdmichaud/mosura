<p align="center">
  <img src="assets/logo.svg" alt="mosura" width="128">
</p>

# mosura

A command-line reimplementation of **Ghidra's logic** (not its UI) in Rust.

A faithful translation of Ghidra's C++ decompiler, validated against Ghidra's own
intermediate IR stage by stage. The **SLEIGH engine** (disassembler + p-code) is done;
the decompiler core is being ported on Ghidra's `Action`/`Rule` architecture. Plan:
[`docs/port-plan.md`](docs/port-plan.md). Correctness is guided by characterization
testing against Ghidra as the golden oracle — see
[`docs/testing-baseline.md`](docs/testing-baseline.md).

## Workspace layout

```
<workspace>/
  ghidra/   pinned Ghidra source checkout (git tag Ghidra_12.0.3_build) — the reference
  mosura/   this project
```

`ghidra/` is the reference source the port is validated against, pinned to Ghidra
**12.0.3** to match the version the oracle runs. Do not bump it casually.

## Prerequisites

A C++ toolchain plus libbfd (the standalone Ghidra tools link against it):

```sh
# Debian/Ubuntu
sudo apt-get install -y build-essential bison flex binutils-dev libbfd-dev zlib1g-dev
```

(Rust/Cargo is needed once port code lands; not required to build the oracle.)

## Setup (one command)

```sh
mosura/scripts/setup-oracle.sh
```

Self-contained: it depends only on the toolchain above and the pinned `ghidra/`
checkout — **not** on any external Ghidra install. It:

1. checks prerequisites and that `ghidra/` is at tag `Ghidra_12.0.3_build`;
2. builds the standalone tools — `sleigh_opt`, `decomp_dbg`, `decomp_test_dbg`;
3. compiles every processor `.slaspec` → `.sla` from source (in place);
4. verifies by running Ghidra's decompiler datatest suite (**expects 599/599**).

Options: `--skip-specs` (reuse already-compiled `.sla`), `--verify-only`.
Override the Ghidra location with `GHIDRA_SRC=/path/to/ghidra`.

It writes `mosura/build/oracle.env` — source it to locate the tools from any script:

```sh
source mosura/build/oracle.env
"$DECOMP_TEST_DBG" -sleighpath "$GHIDRA_SRC" -path "$DATATESTS" datatests
```

## The oracle

After setup you have a fully-offline reference oracle:

| Tool | Purpose |
|------|---------|
| `sleigh_opt`      | SLEIGH spec compiler (`.slaspec` → `.sla`) |
| `decomp_dbg`      | interactive decompiler console; `print raw` dumps p-code |
| `decomp_test_dbg` | native datatest runner (599/599 on the pinned tree) |

A **secondary, optional** oracle is the GhidraMCP server (Java), used for
cross-checking and for stages the C++ tools don't cover (loaders, analysis). It is
not required for the SLEIGH-engine baseline, and its install path is not a mosura
dependency.

## Conformance harness (milestone 1)

The Rust harness (`crates/mosura`) holds the test baseline against the oracle:

```sh
cargo test            # run the harness
cargo xtask baseline  # regenerate disasm/p-code goldens from oracle/fixtures/
```

- `datatest.rs` reads Ghidra's datatest XML; `tests/conformance_datatests.rs`
  ingests all 79 fixtures (599 assertions — exactly the oracle's count) and holds a
  **red-baseline ratchet** for decompiler parity (`0/599` today; oracle = 599/599).
- `oracle/capture.cc` (built by the setup script) captures disasm + raw p-code
  **offline** for fixtures in `oracle/fixtures/` into `goldens/disasm/`;
  `tests/disasm_golden.rs` ratchets mosura's SLEIGH runtime against them.

As the SLEIGH engine lands, the ratchet constants (`EXPECTED_DATATEST_PASS`,
`EXPECTED_DISASM_PASS`) get bumped — the baseline turns from red toward 599/599.

## Port status

The SLEIGH runtime port (stage 1b) is byte-exact on x86-64 **and** AARCH64, with a
working p-code interpreter. Built bottom-up:

- ✅ **`.sla` loader** (`sleigh::sla`) — decompresses + decodes Ghidra's compiled
  PackedDecode tables into an element tree. Verified against Ghidra's own
  `sleigh_opt -y` serialization (`tests/sla_decode.rs`: 5228 elements, header, and
  space table all match).
- ✅ **SLEIGH engine** (`sleigh::engine`) — interprets the tables into a working
  disassembler + p-code lifter: spaces, symbol table, constructors, match
  patterns, the decision tree, **and context** (built from the `.pspec` defaults).
  Per instruction: walk the tree → match a constructor → render display pieces →
  expand the p-code template.
  Includes **operand resolution**: descend into constructor operands, recurse into
  sub-constructor subtables, resolve register lists (`attach variables`), and
  evaluate token-field immediates — with operand-aware instruction length.
  - **6502** (`tests/disasm_6502.rs`): `NOP`/`CLC`/`SEC` fully match the golden
    (disasm + p-code); `LDA #0x5` disassembles correctly (2-byte length).
  - **x86-64 disassembly: 100% on a differential corpus.** `tests/coverage_x86_64.rs`
    disassembles **127 diverse real instructions** (compiled C — `MOV`/`LEA`/`IMUL`/
    `DIV`/`CMOVcc`/`Jcc`/`MOVZX`/`MOVSXD`/SIB/REX/…) and diffs **every one** against
    the Ghidra oracle: **127/127**. Engine features added to get there — each fixing
    a whole instruction *class*, not one instruction:
    context changes (REX prefixes: 47%→79%), relative-branch targets, ValueMap (SIB
    scale), OperandValue (out-of-band, for context ops), and R8-R15 extension
    (96%→100%). This is the data-driven payoff — mosura interprets Ghidra's 4,576
    instruction constructors generically; we add interpreter features, not
    instructions.
- ✅ **x86-64 stage 1b complete on the corpus: 100% disasm + p-code.** The
  coverage test now checks **p-code too** (the plan's exact-match measure):
  **127/127**. Added operand handles (`HandleTpl::fix`, `BUILD` expansion,
  `ConstTpl::Handle` selectors) and **dynamic memory handles** — `[RDI]` /
  `[RAX + RDX*8]` lift to `LOAD`/`STORE` through the computed pointer. So
  MOV/AND/CMP/memory ops all produce byte-exact raw p-code.
- ✅ **p-code interpreter** (`sleigh::emu`) — executes the lifted raw p-code over a
  byte-addressable machine, **following branches/loops**. `tests/semantic_x86_64.rs`
  proves the **semantics** are right by *executing* it: `a*3+(b>>2)-5` and a real
  loop `sumto(n)=n*(n+1)/2` (1000+ iterations) compute correctly — which
  text-matching alone can't guarantee.
- ✅ **Engine wired into `sleigh::disassemble`** via a language registry
  (`lang.rs`: resolves any Ghidra language id → `.sla` + default context from the
  `.ldefs`/`.pspec`). `tests/disasm_golden.rs` ratchets the engine over **every**
  fixture through the public API.
- ✅ **Six architectures at 100% disasm + p-code with _zero_ arch-specific code:
  254/254.** The same engine lifts **x86-64, AARCH64, 6502, ARM, MIPS (big *and*
  little-endian), and PowerPC (big-endian)** — proving the data-driven thesis: we
  port the SLEIGH *interpreter*, not ISAs. Getting cross-arch to 100% needed only
  generic engine features: **MIPS/SPARC delay slots** (`SleighBuilder::delaySlot`),
  the full float/extract op-name table, const-offset masking, and chunk-boundary
  loader semantics. ARM conditional execution and big-endian already worked.
- 🟡 **Decompiler: bytes → typed C, eleven function classes, scored against Ghidra.**
  (`decomp::`, plan in [`docs/decompiler-plan.md`](docs/decompiler-plan.md)) — Ghidra's
  action pipeline, ported bottom-up: **D0** structured IR + CFG, **D1** full SSA (CHK
  dominators, dominance frontiers, Cytron renaming), **D2** dead code + simplification
  identities, **D3** stack-variable recovery + initial types (pointers, `uint`), **D4**
  control-flow structuring (`?:`, `if`/`else`, do-while, guarded while, **`for`/`while`**
  loops with statement bodies), and **D5** C emission + a structural comparator. It
  decompiles straight-line code, conditionals, loops, **function calls** (convention +
  argument recovery), **`-O0` stack frames**, **pointer stores** (`*p = x`), and
  **`void`** functions — e.g. `for(i=0;i<n;i++) s+=i;` and `int f(int *p,int x){*p=x;…}`
  recover near-exactly. **D6**: against the real x86-64 decompiler datatests, mosura
  decompiles **47/62**, averaging **0.56** structural similarity to Ghidra's own C
  (`tests/datatest_score.rs`, scored via `oracle/capture --c`). Remaining toward the
  datatest 599: floats, switch recovery, structs/globals, nested control flow.
- ⏳ Also queued: the `pcodetest` C suite (needs per-arch cross-compilers); SSE/AVX.

## Moving to another machine

Copy the workspace (or re-create `ghidra/` at tag `Ghidra_12.0.3_build`), install the
prerequisites, and run `scripts/setup-oracle.sh`. All build artifacts (`*.sla`, the
tool binaries, `mosura/build/`) are regenerated and are git-ignored.
