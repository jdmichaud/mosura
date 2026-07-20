#!/usr/bin/env bash
#
# build.sh — build the cross-compiler self-compiled GROUND-TRUTH corpus (task #3, phase 1).
#
# For each (program × compiler × arch) it: (1) compiles an UNSTRIPPED binary, (2) DERIVES the
# ground-truth facts from the build artifact itself — `nm`/`objdump` of the unstripped binary,
# never hand-authored — into a diffable `.truth` file, then (3) STRIPS the binary to the
# analyzed artifact. The stripped binary + the `.truth` file are committed (the test surface);
# this script + the toolchains are dev-oracle (regeneration only) — docs/dependencies.md.
#
# The truth is the ORACLE: it comes from the source/build we own, NOT from Ghidra (which is
# often wrong). `tests/ground_truth_parity.rs` checks mosura's analysis of the stripped binary
# against it (functions recovered as a clean subset with recall; the switch dispatch present).
#
# Phase-1 slice: the x86-64 gcc column only (report + review before scaling the matrix). The
# `build_one` rows below are how the matrix grows: add a row per compiler×arch. Absent
# toolchains are skipped with a note (never faked). No absolute paths.
set -euo pipefail
cd "$(dirname "$0")"

log() { printf '\033[1;34m[gt]\033[0m %s\n' "$*"; }

# Derive the .truth file for an unstripped binary via nm + objdump (build-derived, not Ghidra).
#   $1 unstripped binary   $2 program   $3 compiler   $4 arch   $5 mosura-lang-id
#   $6 objdump/nm tool prefix (e.g. "" for host, "riscv64-linux-gnu-" for a cross target)
derive_truth() {
  local bin="$1" prog="$2" cc="$3" arch="$4" lang="$5" pfx="${6:-}"
  local nm="${pfx}nm" objdump="${pfx}objdump"
  local truth="$prog.$cc-$arch.truth"
  {
    echo "# mosura-ground-truth v1 program=$prog compiler=$cc arch=$arch lang=$lang"
    echo "# derived-from=$(basename "$bin") via=nm+objdump (build artifact, NOT Ghidra)"
    echo "compiler $cc"
    # ELF entry point (survives stripping; mosura seeds analysis from it).
    local entry
    entry=$("$objdump" -f "$bin" | awk '/start address/ {print $NF}')
    echo "entry ${entry#0x}"
    # Functions: defined text symbols (t/T/w/W) with size, from the symbol table.
    "$nm" -S --defined-only "$bin" \
      | awk 'tolower($3) ~ /^[tw]$/ {printf "func %s %s %s\n", $1, $2, $4}' \
      | sort
    # Switch dispatches: indirect jumps (`jmp *reg` / `jmp *mem`) — a jump-table computed jump.
    "$objdump" -d "$bin" \
      | awk '/\tjmp +\*/ {gsub(/:/,"",$1); printf "switch %s\n", $1}' \
      | sort
  } > "$truth"
  log "  derived $truth ($(grep -c '^func ' "$truth") funcs, $(grep -c '^switch ' "$truth") switch)"
}

# Build one (program, compiler, arch) cell: compile unstripped, derive truth, strip.
#   $1 program  $2 compiler-tag  $3 arch-tag  $4 mosura-lang  $5 compiler cmd  $6 tool prefix
build_one() {
  local prog="$1" cc="$2" arch="$3" lang="$4" cmd="$5" pfx="${6:-}"
  local unstripped="$prog.$cc-$arch.unstripped" stripped="$prog.$cc-$arch"
  log "$prog [$cc/$arch]"
  # shellcheck disable=SC2086
  $cmd -o "$unstripped" "src/$prog.c"
  derive_truth "$unstripped" "$prog" "$cc" "$arch" "$lang" "$pfx"
  "${pfx}strip" -o "$stripped" "$unstripped"
  rm -f "$unstripped"   # transient — only the stripped binary + .truth are committed
}

# --- Phase-1 slice: x86-64 gcc (freestanding, -O2 so the switch becomes a jump table) --------
GCC_X64="gcc -nostdlib -static -no-pie -O2 -ffreestanding -fno-asynchronous-unwind-tables"
for prog in arith dispatch; do
  build_one "$prog" gcc x86-64 "x86:LE:64:default" "$GCC_X64" ""
done

# --- Matrix to scale into (Phase 2, after review). Each is one build_one row. Toolchains that
#     are present per the manifest: gcc-aarch64/riscv64/m68k, sdcc (z80), Watcom wcc386.
#     ABSENT here: clang, MSVC (documented gaps in docs/ground-truth-corpus.md — never faked).
# build_one dispatch gcc aarch64 "AARCH64:LE:64:v8A"  "aarch64-linux-gnu-gcc -nostdlib -static -O2 -ffreestanding -fno-asynchronous-unwind-tables" "aarch64-linux-gnu-"
# build_one dispatch gcc riscv64 "RISCV:LE:64:default" "riscv64-linux-gnu-gcc -nostdlib -static -O2 -ffreestanding -fno-asynchronous-unwind-tables" "riscv64-linux-gnu-"
# ... m68k gcc, z80 sdcc, x86-32 Watcom wcc386 (per-arch entry shim — see the design doc).

log "done — committed artifacts: *.gcc-x86-64 (stripped) + *.gcc-x86-64.truth"
