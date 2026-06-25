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

echo "built:"
for f in freestanding.elf basic.elf switchtab.elf; do printf '  %-18s ' "$f"; file -b "$f"; done
