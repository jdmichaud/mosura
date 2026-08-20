#!/usr/bin/env bash
# war2-smoke — the ~3-minute gate to run BEFORE any corpus round (docs/byte-exact-status.md
# sb99 retrospective; memory: experiment-discipline). Emits the whole tree (the emit is
# whole-program, ~100s) but COMPILES only the pinned smoke set: mechanism-sensitive EXACTs
# (one sentinel per landed recovery: extrapop, param-order, volatile, cdecl family, thunk,
# contract-sensitive allocs) plus stable MISMATCH/residue sentinels, so drift in EITHER
# direction fails. Catches wrong models AND harness/state corruption (stale binary,
# poisoned -dirty caches, pipeline-corrupting mutations) in minutes instead of a
# 45-minute corpus round.
#
# usage: scripts/war2-smoke.sh [out-dir]     (default /data/be2/smoke)
set -euo pipefail
cd "$(dirname "$0")/.."

EXE=${WAR2_EXE:-/home/jd/WAR2.EXE}
WATCOM=${WAR2_WATCOM:-/home/jd/projects/warcraft2-re/tmp/watcom-experiments/watcom_10.0a/WATCOM}
CACHE=${WAR2_CACHE:-/data/be2/cache}
OUT=${1:-/data/be2/smoke}
TARGET=${CARGO_TARGET_DIR:-/data/mosura-target}
EXPECT=scripts/war2-smoke.expected.tsv

CARGO_TARGET_DIR=$TARGET cargo build --release --example war2_survey --example recompile_check

mkdir -p "$OUT"
# A stale -dirty param-order cache from a broken binary poisons the emit silently
# (war2-remeasure runbook) — the smoke tree always re-derives.
rm -f "$OUT"/param-orders.*-dirty.tsv
"$TARGET/release/examples/war2_survey" "$EXE" "$OUT" > "$OUT/emit.log" 2>&1
MANIFEST=$(sed -n 's/^manifest: //p' "$OUT/emit.log" | tail -1)

IDS=$(awk -F'\t' '!/^#/{print $1}' "$EXPECT" | paste -sd,)
"$TARGET/release/examples/recompile_check" "$EXE" "$MANIFEST" "$OUT/recovered" recover \
    "$WATCOM" --cache "$CACHE" --only "$IDS" --out "$OUT/smoke-verdicts.tsv" \
    > "$OUT/check.log" 2>&1

fail=0
while IFS=$'\t' read -r idx va name expected; do
    [[ $idx == \#* ]] && continue
    got=$(awk -F'\t' -v v="$va" '$2==v{print $4}' "$OUT/smoke-verdicts.tsv")
    if [[ "$got" != "$expected" ]]; then
        echo "SMOKE DRIFT: $name ($va) expected $expected got ${got:-<absent>}"
        fail=1
    fi
done < "$EXPECT"

if [[ $fail -ne 0 ]]; then
    echo "war2-smoke: FAIL — do not run a corpus round; diagnose the drift first."
    exit 1
fi
echo "war2-smoke: OK ($(grep -cv '^#' "$EXPECT") sentinels hold)"
