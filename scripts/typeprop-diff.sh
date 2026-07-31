#!/usr/bin/env bash
#
# typeprop-diff.sh — the TYPE-side twin of trace-diff.sh (task #11).
#
# WHY IT EXISTS. trace-diff.sh drives Ghidra's OPACTION_DEBUG, which is a p-code-OP mutation log:
# debugModCheck takes a PcodeOp*, debugModPrint early-outs on `modify_list.empty()`
# (funcdata.cc:1012/1035). ActionInferTypes assigns Datatype* to VARNODES and mutates no ops, so it
# NEVER prints there — on either side. `infertypes` fires zero times in BOTH traces on every
# fixture, which reads as agreement and is really invisibility. This script drives the OTHER debug
# channel Ghidra ships for exactly that reason.
#
#   ghidra : oracle/capture_typeprop  -> ActionInferTypes::propagationDebug (coreaction.cc:4980),
#            whose main call site is inside propagateTypeEdge at the typeOrder comparison
#            (coreaction.cc:5105) — i.e. every ACCEPTED type decision, with the op+slot it came from
#   mosura : MOSURA_TYPEPROP=1       -> infertypes.rs propagation_debug(), the same tuple
#
# Neither needs a special build: types.h:88-91 auto-defines TYPEPROP_DEBUG from CPUI_DEBUG, exactly
# like OPACTION_DEBUG, so the hook is already in the libdecomp_dbg.a the oracle links. Only the
# RUNTIME flag is extra (TypeFactory::propagatedbg_on, default false, type.cc:3101).
#
# ⚠️ WHAT THIS DOES *NOT* DO, DELIBERATELY. It does not join the two sides per varnode. Ghidra
# prints `CL(0x00100033:da)` and mosura prints `r0x8:4(0x10001b:74)#494` — register name vs raw
# offset, hex vs decimal sequence numbers — and a varnode IDENTITY MAP between the two engines does
# not exist yet. Inventing an approximate one would let the instrument report false agreement, which
# is the failure mode this whole family of tools was rebuilt to avoid. So it prints both traces and
# the comparisons that ARE sound without an identity map: the per-side distribution of varnode
# WIDTHS and TYPE names, and every constant by (value, size). That is what exposed the first real
# finding — on orcompare, Ghidra's chain is 1-byte throughout (`#0x1:1`, `#0x2:1`, `char`) where
# mosura's is 4-byte (`#0x1:4`, `#0x2:4`, `Int(4)`) — which relocated the divergence from type
# inference to the sub-variable narrowing UPSTREAM of it.
#
# Usage:   scripts/typeprop-diff.sh <fixture-stem>
# Env:     GHIDRA_SRC   pinned Ghidra checkout (default: <workspace>/ghidra)
#          KEEP=1       keep the raw traces instead of a temp dir
#
set -euo pipefail

STEM="${1:?usage: typeprop-diff.sh <fixture-stem>}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MOSURA_DIR="$(dirname "$SCRIPT_DIR")"
WORKSPACE="$(dirname "$MOSURA_DIR")"
GHIDRA_SRC="${GHIDRA_SRC:-$WORKSPACE/ghidra}"
FIXTURE="$GHIDRA_SRC/Ghidra/Features/Decompiler/src/decompile/datatests/$STEM.xml"
TOOL="$MOSURA_DIR/oracle/capture_typeprop"

[ -x "$TOOL" ] || { echo "missing $TOOL — run scripts/setup-oracle.sh" >&2; exit 1; }
[ -f "$FIXTURE" ] || { echo "no fixture $FIXTURE" >&2; exit 1; }

OUT="$(mktemp -d)"
trap '[ -n "${KEEP:-}" ] || rm -rf "$OUT"' EXIT

# Same provenance discipline as trace-diff.sh: a trace that cannot be attributed to a tree state has
# already caused one wrong attribution on this project.
sha="$(cd "$MOSURA_DIR" && git rev-parse --short HEAD 2>/dev/null || echo UNKNOWN)"
if (cd "$MOSURA_DIR" && ! git diff --quiet -- crates/ 2>/dev/null); then sha="${sha}+DIRTY"; fi
grev="$(cd "$GHIDRA_SRC" && git rev-parse --short HEAD 2>/dev/null || echo PINNED)"

"$TOOL" "$GHIDRA_SRC" "$FIXTURE" --typeprop 2>/dev/null > "$OUT/ghidra.typeprop"
( cd "$MOSURA_DIR" && MOSURA_TYPEPROP=1 cargo run -q --release --example trace -- "$STEM" 2>&1 >/dev/null \
    | grep '^TYPEPROP ' > "$OUT/mosura.typeprop" ) || true

echo "=== ghidra: rev=$grev fixture=$STEM   ($(wc -l < "$OUT/ghidra.typeprop") decisions)"
echo "=== mosura: sha=$sha fixture=$STEM   ($(wc -l < "$OUT/mosura.typeprop") decisions)"
python3 "$SCRIPT_DIR/typeprop-diff.py" "$OUT/ghidra.typeprop" "$OUT/mosura.typeprop"
[ -n "${KEEP:-}" ] && echo -e "\ntraces kept: $OUT/ghidra.typeprop  $OUT/mosura.typeprop"
exit 0
