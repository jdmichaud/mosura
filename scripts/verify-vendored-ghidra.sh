#!/usr/bin/env bash
# verify-vendored-ghidra.sh — prove the vendored third_party/ghidra subset is byte-identical
# to the pinned checkout (and refresh it after a pin bump).
#
# The vendored copy (see third_party/ghidra/README.md) is what makes `cargo test`
# self-contained. Its integrity contract: byte-verbatim files from the checkout at the pin,
# plus the deterministic .sla compile of that pin. This script enforces the contract:
#
# Covers, per processor: data/languages (SLEIGH specs + compiled .sla) and data/patterns (the
# Function Start Search byte patterns; absent for Z80, which ships none).
#
#   verify (default):  diff every vendored file against the checkout. Refuses to run if the
#                      checkout is not at the pinned commit (a diff against the wrong pin
#                      proves nothing). Exit 1 on any difference.
#   --refresh:         re-copy the subset from the (pin-verified) checkout — use after a pin
#                      bump (run setup-ghidra.sh first so the new .sla exist), then commit.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"           # mosura-analysis/
GHIDRA_SRC="${GHIDRA_SRC:-$(cd "$HERE/.." && pwd)/ghidra}"
VENDORED="$HERE/third_party/ghidra"
PIN="09f14c92d3da6e5d5f6b7dea115409719db3cce1"                    # Ghidra_12.0.3_build
PROCESSORS=(x86 AARCH64 RISCV 68000 Z80 ARM 6502 MIPS PowerPC)

[ -d "$GHIDRA_SRC/Ghidra/Processors" ] || { echo "ERROR: no Ghidra checkout at $GHIDRA_SRC (run scripts/setup-ghidra.sh)"; exit 1; }
at="$(git -C "$GHIDRA_SRC" rev-parse HEAD 2>/dev/null || echo unknown)"
[ "$at" = "$PIN" ] || { echo "ERROR: checkout at $at, not the pin $PIN — refusing (nothing would be proven)"; exit 1; }

if [ "${1:-}" = "--refresh" ]; then
  echo "[vendored] refreshing from the pin-verified checkout …"
  for p in "${PROCESSORS[@]}"; do
    rm -rf "$VENDORED/Processors/$p/data/languages" "$VENDORED/Processors/$p/data/patterns"
    mkdir -p "$VENDORED/Processors/$p/data"
    cp -r "$GHIDRA_SRC/Ghidra/Processors/$p/data/languages" "$VENDORED/Processors/$p/data/"
    # data/patterns is the Function Start Search input; not every processor ships one (Z80 does not).
    if [ -d "$GHIDRA_SRC/Ghidra/Processors/$p/data/patterns" ]; then
      cp -r "$GHIDRA_SRC/Ghidra/Processors/$p/data/patterns" "$VENDORED/Processors/$p/data/"
    fi
  done
  rm -rf "$VENDORED/datatests"
  cp -r "$GHIDRA_SRC/Ghidra/Features/Decompiler/src/decompile/datatests" "$VENDORED/datatests"
  cp "$GHIDRA_SRC/LICENSE" "$GHIDRA_SRC/NOTICE" "$VENDORED/"
  echo "[vendored] refreshed — review + commit (and bump PIN in this script if it changed)"
  exit 0
fi

fail=0
for p in "${PROCESSORS[@]}"; do
  diff -r "$GHIDRA_SRC/Ghidra/Processors/$p/data/languages" "$VENDORED/Processors/$p/data/languages" \
    || { echo "MISMATCH: $p languages"; fail=1; }
  if [ -d "$GHIDRA_SRC/Ghidra/Processors/$p/data/patterns" ]; then
    diff -r "$GHIDRA_SRC/Ghidra/Processors/$p/data/patterns" "$VENDORED/Processors/$p/data/patterns" \
      || { echo "MISMATCH: $p patterns"; fail=1; }
  elif [ -d "$VENDORED/Processors/$p/data/patterns" ]; then
    echo "MISMATCH: $p patterns vendored but absent from the pin"; fail=1
  fi
done
diff -r "$GHIDRA_SRC/Ghidra/Features/Decompiler/src/decompile/datatests" "$VENDORED/datatests" \
  || { echo "MISMATCH: datatests"; fail=1; }
[ $fail = 0 ] && echo "[vendored] OK — third_party/ghidra is byte-identical to the pin ($PIN)"
exit $fail
