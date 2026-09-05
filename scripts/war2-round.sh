#!/bin/bash
# One WAR2 corpus round: [smoke] → emit → recompile_check (with divergence rows) → verdicts vs a baseline.
# usage: scripts/war2-round.sh <new> <baseline> "<label>" [skipsmoke]   e.g. war2-round.sh zc35 zc34 "what changed"
# Per docs/war2-recompile-remeasure.md: flags arg is the literal `recover`; binaries from CARGO_TARGET_DIR (rebuild first).
set -uo pipefail
NEW=$1; BASE=$2; LABEL=$3; SKIP=${4:-}
cd "$(dirname "${BASH_SOURCE[0]}")/.."
. scripts/devcfg.sh
export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-/data/mosura-target}
EX=$CARGO_TARGET_DIR/release/examples
WAT="$(devcfg watcom.install "$HOME/watcom")"
EXE="$(devcfg binaries.war2 "$HOME/WAR2.EXE")"
CACHE="$(devcfg recompile.cache "${TMPDIR:-/tmp}/mosura-recompile-cache")"
if [ -z "$SKIP" ]; then echo "== smoke start $(date +%T)"; timeout 3000 scripts/war2-smoke.sh 2>&1 | tail -3; echo "== smoke done $(date +%T)"; fi
OUT=/data/be2/$NEW
rm -rf $OUT; mkdir -p $OUT
echo "== emit start $(date +%T)"
timeout 1800 $EX/war2_survey "$EXE" $OUT > $OUT/emit.log 2>&1; echo "emit rc=$?"
MANIFEST=$(sed -n 's/^manifest: //p' $OUT/emit.log | tail -1)
echo "== check start $(date +%T)"
timeout 5400 $EX/recompile_check "$EXE" "$MANIFEST" $OUT/recovered recover "$WAT" --cache "$CACHE" --out /data/be2/$NEW-rec.tsv --divergences /data/be2/$NEW-div.tsv > $OUT/check.log 2>&1; echo "check rc=$?"
echo "== $NEW ($LABEL) vs $BASE == $(date +%T)"
scripts/war2-verdicts.sh /data/be2/$BASE-rec.tsv /data/be2/$NEW-rec.tsv
