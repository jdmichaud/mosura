<p align="center">
  <img src="assets/logo.svg" alt="mosura" width="128">
</p>

# mosura

[![CI](https://github.com/jdmichaud/mosura/actions/workflows/ci.yml/badge.svg)](https://github.com/jdmichaud/mosura/actions/workflows/ci.yml)

## What it is

**mosura** is a faithful reimplementation of [Ghidra](https://ghidra-sre.org/)'s reverse-engineering
logic — the SLEIGH disassembler, the p-code interpreter and the C decompiler — as a Rust library with a
C API, and a command-line tool built on it. Every stage is a from-source port of Ghidra's own C++,
validated against Ghidra itself as the golden oracle. There is no UI.

On top of the port, mosura recovers *compilable* C: it emits a translation unit per function, compiles it
with the program's original toolchain, and judges the result against the original bytes — byte-exact or
not, and if not, how the two differ — or by differential execution when the bytes are not the question.

- **SLEIGH engine.** One data-driven interpreter runs every language in the vendored Ghidra 12.0.3
  processor tables — 89 language variants across the x86, ARM, AArch64, MIPS, PowerPC, 68000, RISC-V,
  Z80 and 6502 families. Disassembly and p-code goldens pin nine architectures against Ghidra.
- **Decompiler.** A port of Ghidra's `Action`/`Rule` pipeline: SSA heritage, the simplification rules,
  type/stack/argument recovery, jump tables, control-flow structuring and C emission, scored continuously
  against Ghidra's own C.
- **Analysis.** Loaders for ELF, PE, MZ, LE/LX, X-32, CP/M `.com`, raw images and Ghidra XML fixtures, plus
  OMF and REL object files; auto-analysis to convergence; FID library identification.
- **Recompilation.** The recovered emission (Watcom x86-32 today), compilation through a toolchain driver,
  byte-level verdicts, corpus rounds with gates, and a differential-execution equivalence check.
- **Library first.** `libmosura` with a generated, committed C header ([`include/mosura.h`](include/mosura.h)),
  a Rust binding, and a CLI in which every capability is a registered operation over a flat,
  content-addressed session store.

mosura is early-stage.

## How to use

A bare clone builds and runs with a Rust toolchain ([rustup](https://rustup.rs/)) alone: the processor
tables, mosura's compiler specs and its FID databases are embedded at build time. No Ghidra checkout, no
environment variable.

```sh
cargo build --release -p mosura-cli                        # the `mosura` binary (target/release/mosura)
mosura identify <binary>                                   # what is this file? container, loader, compiler, language, FID
mosura -S work add <binary>                                # a session is a directory; the input is content-addressed
mosura -S work analyze                                     # auto-analysis, cached by content + options
mosura -S work functions                                   # tables: functions symbols refs blocks listing … (--format text|tsv|json)
mosura -S work decompile 0x401000                          # C for one function (a name works too); --as raw for the IR
mosura -S work emit 0x401000                               # the compilable translation unit; --all --out DIR for every function
mosura lift 5589e5c3                                       # raw bytes → p-code (--language ID); `disasm --bytes …` disassembles
mosura ops                                                 # every operation; `mosura call <op> key=value …` reaches each one
```

Recompilation needs the program's toolchain on this machine:

```sh
mosura -S work toolchain add watcom --spec watcom-10.0a-dos --install <WATCOM dir>
mosura -S work recompile 0x401000 --toolchain watcom       # emit → compile → verify one function (--all for every one)
mosura -S work round run r1 --toolchain watcom             # the corpus round: verdicts, divergences, gates (--baseline r0 to compare)
mosura -S work equiv 0x401000 --toolchain watcom           # differential execution: is the recovered C faithful?
```

`-S -` gives an in-memory session for one-shot commands; `--data-dir <dir>` overrides the embedded data
file by file; `--format json` on any command prints its table as JSON. The same capabilities are reachable
from any language through the C API — `cargo xtask dist` stages `dist/{libmosura.so, libmosura.a, mosura.h,
mosura}` — and from Rust through the `mosura` crate.

## Developing

[`docs/development.md`](docs/development.md): the crates, the layout, the oracle setup, the tests, the
developer tier, how a change is measured, and the guards. The porting principle and the workflow are in
[`AGENTS.md`](AGENTS.md).

## License

Licensed under the **Apache License 2.0** (declared in the workspace `Cargo.toml`), matching Ghidra's own
license. mosura is a from-source port of Ghidra and links no GPL-licensed code.
