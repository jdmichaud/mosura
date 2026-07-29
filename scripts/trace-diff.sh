#!/usr/bin/env bash
#
# trace-diff.sh — one-command rule-application trace diff for a fixture (Task #2).
#
# Runs Ghidra's canonical OPACTION_DEBUG trace (oracle/capture_trace) and mosura's own trace
# (MOSURA_TRACE=1, examples/trace.rs) over the same datatest fixture, then diffs the two rule-firing
# sequences with scripts/trace-diff.py — surfacing which rules Ghidra fires that mosura doesn't (and
# where the two diverge). Both traces are off by default in normal builds; this is a diagnostic.
#
# Usage:   scripts/trace-diff.sh <fixture-stem>          # e.g. piecestruct, orcompare, nan
# Env:     GHIDRA_SRC   pinned Ghidra checkout (default: <workspace>/ghidra)
#          KEEP=1       keep the raw .trace files (printed paths) instead of a temp dir
#
set -euo pipefail

STEM="${1:?usage: trace-diff.sh <fixture-stem>}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MOSURA_DIR="$(dirname "$SCRIPT_DIR")"
WORKSPACE="$(dirname "$MOSURA_DIR")"
GHIDRA_SRC="${GHIDRA_SRC:-$WORKSPACE/ghidra}"
FIXTURE="$GHIDRA_SRC/Ghidra/Features/Decompiler/src/decompile/datatests/$STEM.xml"
CAPTURE_TRACE="$MOSURA_DIR/oracle/capture_trace"

[ -x "$CAPTURE_TRACE" ] || { echo "missing $CAPTURE_TRACE — run scripts/setup-oracle.sh" >&2; exit 1; }
[ -f "$FIXTURE" ] || { echo "no fixture $FIXTURE" >&2; exit 1; }

OUT="$(mktemp -d)"
trap '[ -n "${KEEP:-}" ] || rm -rf "$OUT"' EXIT

# PROVENANCE STAMP — the mosura trace records the exact tree it was produced from.
# This exists because a trace was once produced from a CLEAN tree and then compared as though it
# were the patched one, and the resulting rule-firing deltas were reported as a patch's defect when
# they were the baseline's. `git stash`/`git apply` between runs makes that a one-keystroke mistake
# and no amount of care prevents it; the stamp does. trace-diff.py refuses to run without it.
mosura_stamp() {
  local sha dirty
  sha="$(cd "$MOSURA_DIR" && git rev-parse --short HEAD 2>/dev/null || echo UNKNOWN)"
  if (cd "$MOSURA_DIR" && ! git diff --quiet -- crates/ 2>/dev/null); then dirty="+DIRTY"; else dirty=""; fi
  echo "# MOSURA-TRACE-STAMP sha=${sha}${dirty} fixture=${STEM} produced=$(date -Is)"
}
ghidra_stamp() {
  local rev
  rev="$(cd "$GHIDRA_SRC" && git rev-parse --short HEAD 2>/dev/null || echo PINNED)"
  echo "# GHIDRA-TRACE-STAMP rev=${rev} fixture=${STEM} produced=$(date -Is)"
}

ghidra_stamp > "$OUT/ghidra.trace"
"$CAPTURE_TRACE" "$GHIDRA_SRC" "$FIXTURE" --trace >> "$OUT/ghidra.trace" 2>/dev/null
mosura_stamp > "$OUT/mosura.trace"
( cd "$MOSURA_DIR" && MOSURA_TRACE=1 cargo run -q --example trace -- "$STEM" >> "$OUT/mosura.trace" 2>/dev/null )

python3 "$SCRIPT_DIR/trace-diff.py" "$OUT/ghidra.trace" "$OUT/mosura.trace"
[ -n "${KEEP:-}" ] && echo -e "\ntraces kept: $OUT/ghidra.trace  $OUT/mosura.trace"
exit 0
