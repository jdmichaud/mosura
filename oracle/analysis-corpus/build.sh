#!/usr/bin/env bash
# Rebuild the auto-analysis oracle corpus (A0; docs/analysis-port-plan.md).
#
# The built ELFs are committed so the goldens stay toolchain-stable — run this
# only to add/regenerate a corpus binary, then re-capture its snapshot (see
# oracle/analysis-capture.md) and commit both.
#
# Kept tiny and deterministic on purpose: small binaries => reviewable goldens.
set -euo pipefail
cd "$(dirname "$0")"

# Freestanding (no libc/CRT/eh_frame): converged state is just our functions.
gcc -nostdlib -static -no-pie -O0 -ffreestanding -fno-asynchronous-unwind-tables \
    -o freestanding.elf src/freestanding.c

# Realistic dynamically-linked ELF: exercises CRT + PLT thunks + the EXTERNAL block.
gcc -O0 -fno-pie -no-pie -o basic.elf src/basic.c

# Dense switch -> jump table (BRANCHIND), -O2: the index lives in a register with a
# register guard (cmp edi,N; ja .cold below entry) — the realistic optimized form. Validates
# the A6 decompiler-driven switch analyzer.
gcc -nostdlib -static -no-pie -O2 -ffreestanding -fno-asynchronous-unwind-tables \
    -o switchtab.elf src/switchtab.c

# Freestanding C++ (no libstdc++/CRT): namespaced + overloaded + const-method functions
# whose *mangled* names land in .symtab. Validates the A7 GNU/Itanium demangler analyzer.
g++ -nostdlib -static -no-pie -O0 -ffreestanding -fno-asynchronous-unwind-tables \
    -fno-exceptions -fno-rtti -o cppsym.elf src/cppsym.cpp

# Freestanding AArch64 (ARM64) ELF — mosura's first non-x86 fixture. Same freestanding
# recipe as freestanding.elf but for AARCH64:LE:64:v8A: converged state is just our own
# functions, so the function-listing pipeline gets a clean golden (no PLT/GOT). Built with
# the cross gcc; Ghidra auto-detects AArch64 from e_machine (EM_AARCH64=183).
aarch64-linux-gnu-gcc -nostdlib -static -no-pie -O0 -ffreestanding \
    -fno-unwind-tables -fno-asynchronous-unwind-tables -o aarch64.elf src/aarch64.c

echo "built:"
for f in freestanding.elf basic.elf switchtab.elf cppsym.elf aarch64.elf; do printf '  %-18s ' "$f"; file -b "$f"; done
