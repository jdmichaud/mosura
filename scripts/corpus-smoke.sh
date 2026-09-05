#!/usr/bin/env bash
# corpus-smoke — the ~3-minute gate to run BEFORE any corpus round (docs/byte-exact-status.md
# sb99 retrospective; memory: experiment-discipline). Emits the whole tree (the emit is
# whole-program, ~100s) but COMPILES only the pinned smoke set: mechanism-sensitive EXACTs
# (one sentinel per landed recovery: extrapop, param-order, volatile, cdecl family, thunk,
# contract-sensitive allocs) plus stable MISMATCH/residue sentinels, so drift in EITHER
# direction fails. Catches wrong models AND harness/state corruption (stale binary,
# poisoned -dirty caches, pipeline-corrupting mutations) in minutes instead of a
# 45-minute corpus round.
#
# usage: scripts/corpus-smoke.sh [--bin <subject.exe>] [out-dir]     (default: the first configured [[subject]], /data/be2/smoke)
set -euo pipefail
cd "$(dirname "$0")/.."

. "$(dirname "${BASH_SOURCE[0]}")/devcfg.sh"
# The subject: `--bin <exe>`, else the first configured `[[subject]]` (dev-config.toml).
EXE=""
ARGS=()
while [ $# -gt 0 ]; do case "$1" in --bin) EXE="$2"; shift 2 ;; *) ARGS+=("$1"); shift ;; esac; done
set -- "${ARGS[@]}"
[ -n "$EXE" ] || EXE="$(devcfg_first_subject_path)"
[ -n "$EXE" ] || { echo "corpus-smoke: no --bin and no configured [[subject]] in dev-config.toml" >&2; exit 2; }
WATCOM="$(devcfg watcom.install "$HOME/watcom")"
CACHE="$(devcfg recompile.cache "${TMPDIR:-/tmp}/mosura-recompile-cache")"
OUT=${1:-/data/be2/smoke}
TARGET=${CARGO_TARGET_DIR:-/data/mosura-target}
# The pinned sentinels are the SUBJECT's: `smoke.expected.tsv` in its profile (dev-config `[[subject]]`).
PROFILE="$(devcfg_profile "$EXE")"
EXPECT="$PROFILE/smoke.expected.tsv"
[ -n "$PROFILE" ] && [ -f "$EXPECT" ] || { echo "corpus-smoke: no subject profile with smoke.expected.tsv for $EXE (dev-config [[subject]])" >&2; exit 2; }

CARGO_TARGET_DIR=$TARGET cargo build --release --example corpus_emit --example recompile_check

mkdir -p "$OUT"
# A stale -dirty param-order cache from a broken binary poisons the emit silently
# (remeasure (subject-profile note) runbook) — the smoke tree always re-derives.
rm -f "$OUT"/param-orders.*-dirty.tsv
"$TARGET/release/examples/corpus_emit" "$EXE" "$OUT" > "$OUT/emit.log" 2>&1
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
    echo "corpus-smoke: FAIL — do not run a corpus round; diagnose the drift first."
    exit 1
fi
echo "corpus-smoke: OK ($(grep -cv '^#' "$EXPECT") sentinels hold)"
