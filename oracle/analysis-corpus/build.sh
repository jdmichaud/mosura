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

# Freestanding RISC-V (RV64GC) ELF — same freestanding recipe for RISCV:LE:64:default:
# converged state is just our own functions, so the function-listing pipeline gets a clean
# golden (no PLT/GOT). Built with the cross gcc; Ghidra auto-detects RISC-V from e_machine
# (EM_RISCV=243).
riscv64-linux-gnu-gcc -nostdlib -static -no-pie -O0 -ffreestanding \
    -fno-unwind-tables -fno-asynchronous-unwind-tables -o riscv.elf src/riscv.c

# Freestanding m68k ELF — mosura's first BIG-ENDIAN (and first 32-bit) fixture. Same
# freestanding recipe; Ghidra's ELF opinion (EM_68K=4, big, 32, no variant) resolves this to
# 68000:BE:32:Coldfire. Validates the class/endian-parameterized loader + big-endian analysis
# read paths on 68000:BE:32:Coldfire.
m68k-linux-gnu-gcc -nostdlib -static -no-pie -O0 -ffreestanding \
    -fno-unwind-tables -fno-asynchronous-unwind-tables -o m68k.elf src/m68k.c

# Dynamically-linked m68k ELF — the big-endian/32-bit analog of basic.elf (same source), the
# first DYNAMIC non-x86 fixture. Exercises the loader's dynamic path on big-endian 32-bit:
# PT_INTERP, .dynamic/.dynsym, .rela.plt (RELA + m68k JMP_SLOT), the .plt (m68k memory-indirect
# `jmp ([disp,PC])` thunks) and the synthetic EXTERNAL block — mosura resolves the PLT thunks to
# named external functions (printf, __libc_start_main). Same -no-pie form as basic.elf.
m68k-linux-gnu-gcc -O0 -fno-pie -no-pie -o m68k_dyn.elf src/basic.c

# Zilog Z80 CP/M .COM — mosura's first non-ELF corpus fixture (a raw flat image, no
# container). Compiled with sdcc + a minimal CP/M crt0 (call main; rst 0), linked at the
# TPA (_CODE=0x100), converted to a flat image, and the code bytes extracted from 0x100.
# Ghidra can't auto-detect a raw .COM, so its golden is captured with a manual processor +
# base + entry (see scripts/capture-analysis.sh); mosura's `load_com` encodes the same.
sdcc -mz80 -c --opt-code-size src/z80.c -o z80.rel
sdasz80 -o z80_crt0.rel src/z80_crt0.s
sdldz80 -n -i -b _CODE=0x100 z80.ihx z80_crt0.rel z80.rel
makebin -s 65536 z80.ihx z80.full.bin 2>/dev/null
Z80_END=$(python3 -c "
mx=0
for l in open('z80.ihx').read().splitlines():
    if l.startswith(':') and l[7:9]=='00':
        n=int(l[1:3],16); a=int(l[3:7],16); mx=max(mx,a+n)
print(mx)")
dd if=z80.full.bin of=z80.com bs=1 skip=256 count=$((Z80_END-0x100)) 2>/dev/null
rm -f z80.rel z80_crt0.rel z80.ihx z80.full.bin z80.lk z80.map z80.noi z80.rst z80.sym 2>/dev/null

echo "built:"
for f in freestanding.elf basic.elf switchtab.elf cppsym.elf aarch64.elf riscv.elf m68k.elf m68k_dyn.elf; do printf '  %-18s ' "$f"; file -b "$f"; done
printf '  %-18s ' "z80.com"; file -b "z80.com"
